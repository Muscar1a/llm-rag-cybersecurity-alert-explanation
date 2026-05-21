import functools
import re
from collections import defaultdict

from langchain_qdrant import QdrantVectorStore
from langchain_core.vectorstores import VectorStoreRetriever
from langchain_core.retrievers import BaseRetriever
from langchain_core.documents import Document
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from qdrant_client.models import Filter, FieldCondition, MatchValue
from pydantic import ConfigDict, Field
from .qdrant_store import build_client
from .embeddings import get_embeddings
from .settings import settings

# A1: Detect kernel stack trace chunks (hex offsets, addresses, kernel log timestamps)
_STACK_TRACE_RE = re.compile(
    r'(?:0x[0-9a-f]{4,}'            # hex addresses: 0xffff88816d2c0400
    r'|\+0x[0-9a-f]+/0x[0-9a-f]+'   # offset notation: +0x2a2/0x770
    r'|\[\s*\d{4,}\.\d+\])',         # kernel timestamps: [47200.376770]
    re.IGNORECASE,
)
_NOISE_MATCH_THRESHOLD = 8


def _is_noise_chunk(text: str) -> bool:
    return len(_STACK_TRACE_RE.findall(text)) > _NOISE_MATCH_THRESHOLD


@functools.lru_cache(maxsize=1)
def _get_reranker(model_name: str):
    from sentence_transformers import CrossEncoder
    return CrossEncoder(model_name)


def get_vectorstore() -> QdrantVectorStore:
    return QdrantVectorStore(
        client=build_client(),
        collection_name=settings.qdrant_collection,
        embedding=get_embeddings(),
        content_payload_key="text",
        metadata_payload_key="metadata",
    )


class BalancedRetriever(BaseRetriever):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    vectorstore: QdrantVectorStore
    k: int = 5
    max_per_source: int = 2  # A2: cap per source instead of fixed allocation
    lambda_mult: float = 0.5
    fetch_k_mult: int = 10
    min_score: float = 0.82
    reranker_model: str | None = "cross-encoder/ms-marco-MiniLM-L-6-v2"  # C: None to disable

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        # C: fetch more candidates when reranker will do final selection
        candidate_k = self.k * 4 if self.reranker_model else self.k * 3
        # C: loosen source cap so reranker has diverse pool to pick from
        per_source_cap = self.max_per_source + 1 if self.reranker_model else self.max_per_source

        candidates = self.vectorstore.max_marginal_relevance_search(
            query,
            k=candidate_k,
            fetch_k=self.k * self.fetch_k_mult,
            lambda_mult=self.lambda_mult,
            score_threshold=self.min_score,
        )

        filtered: list[Document] = []
        seen: set[str] = set()
        source_counts: dict[str, int] = defaultdict(int)

        for doc in candidates:
            uid = doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
            if uid in seen:
                continue
            # A1: skip kernel stack trace chunks
            if _is_noise_chunk(doc.page_content):
                continue
            source = doc.metadata.get("source", "unknown")
            # A2: enforce per-source cap
            if source_counts[source] >= per_source_cap:
                continue

            seen.add(uid)
            source_counts[source] += 1
            filtered.append(doc)

        if not self.reranker_model or len(filtered) <= self.k:
            return filtered[:self.k]

        # C: rerank filtered candidates and return top-k
        reranker = _get_reranker(self.reranker_model)
        scores = reranker.predict([(query, doc.page_content) for doc in filtered])
        ranked = sorted(zip(scores, filtered), key=lambda x: x[0], reverse=True)
        return [doc for _, doc in ranked[:self.k]]


def build_retriever(source: str | None = None, k: int = 5) -> BaseRetriever:
    if source:
        search_kwargs: dict = {
            "k": k,
            "fetch_k": k * 4,
            "lambda_mult": 0.6,
            "score_threshold": 0.82,
            "filter": Filter(must=[
                FieldCondition(key="metadata.source", match=MatchValue(value=source))
            ]),
        }
        return get_vectorstore().as_retriever(
            search_type="mmr",
            search_kwargs=search_kwargs,
        )

    return BalancedRetriever(vectorstore=get_vectorstore(), k=k)
