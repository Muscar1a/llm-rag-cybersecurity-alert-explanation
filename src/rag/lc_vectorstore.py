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
    min_score: float = 0.60 # original was 0.82
    reranker_model: str | None = "cross-encoder/ms-marco-MiniLM-L-6-v2"  # C: None to disable

    def __init__(self, **data):
        try:
            import yaml
            import os
            if os.path.exists("params.yaml"):
                with open("params.yaml", "r", encoding="utf-8") as f:
                    p = yaml.safe_load(f)
                ret_p = p.get("retrieval", {})
                data.setdefault("k", ret_p.get("k", 5))
                data.setdefault("lambda_mult", ret_p.get("lambda_mult", 0.5))
                data.setdefault("min_score", ret_p.get("score_threshold", 0.60))
        except Exception:
            pass
        super().__init__(**data)

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        sources = ["mitre", "sigma", "et_rules"]

        # Per-source DENSE retrieval (no MMR): MMR-diversity demotes the
        # correct chunk when a false-friend (e.g. T1499.001) ranks above it.
        per_source: dict[str, list[Document]] = {}
        seen: set[str] = set()
        for source in sources:
            source_filter = Filter(must=[
                FieldCondition(key="metadata.source", match=MatchValue(value=source))
            ])
            candidates = self.vectorstore.similarity_search(
                query,
                k=self.max_per_source * 3,
                filter=source_filter,
            )
            kept: list[Document] = []
            for doc in candidates:
                uid = doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
                if uid in seen:
                    continue
                # A1: skip kernel stack trace chunks
                if _is_noise_chunk(doc.page_content):
                    continue
                seen.add(uid)
                kept.append(doc)
                if len(kept) >= self.max_per_source:
                    break
            per_source[source] = kept

        # Round-robin merge: guarantees each source keeps representation in
        # the final k, so the reranker can no longer drop a whole source.
        merged: list[Document] = []
        idx = 0
        while len(merged) < self.k and any(idx < len(per_source[s]) for s in sources):
            for s in sources:
                if idx < len(per_source[s]):
                    merged.append(per_source[s][idx])
                    if len(merged) >= self.k:
                        break
            idx += 1

        if not self.reranker_model or len(merged) <= 1:
            return merged

        # C: rerank for ORDERING only (no truncation below k -> no source dropped)
        reranker = _get_reranker(self.reranker_model)
        scores = reranker.predict([(query, doc.page_content) for doc in merged])
        ranked = sorted(zip(scores, merged), key=lambda x: x[0], reverse=True)
        for score, doc in ranked:
            doc.metadata["rerank_score"] = float(score)
        return [doc for _, doc in ranked]


def build_retriever(source: str | None = None, k: int = 5) -> BaseRetriever:
    lambda_mult = 0.6
    score_threshold = 0.60
    try:
        import yaml
        import os
        if os.path.exists("params.yaml"):
            with open("params.yaml", "r", encoding="utf-8") as f:
                p = yaml.safe_load(f)
            ret_p = p.get("retrieval", {})
            k = ret_p.get("k", k)
            lambda_mult = ret_p.get("lambda_mult", 0.6)
            score_threshold = ret_p.get("score_threshold", 0.60)
    except Exception:
        pass

    if source:
        search_kwargs: dict = {
            "k": k,
            "fetch_k": k * 4,
            "lambda_mult": lambda_mult,
            "score_threshold": score_threshold,
            "filter": Filter(must=[
                FieldCondition(key="metadata.source", match=MatchValue(value=source))
            ]),
        }
        return get_vectorstore().as_retriever(
            search_type="mmr",
            search_kwargs=search_kwargs,
        )

    return BalancedRetriever(vectorstore=get_vectorstore(), k=k)
