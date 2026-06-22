import functools
import re

from langchain_qdrant import QdrantVectorStore
from langchain_core.retrievers import BaseRetriever
from langchain_core.documents import Document
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue
from pydantic import ConfigDict
from .qdrant_store import build_client
from .embeddings import get_embeddings
from .settings import settings

_PORT_RE  = re.compile(r'\bport (\d+)\b')
_STATE_RE = re.compile(r'\bConnection state (\w+)[:\s]')
_CAT_RE   = re.compile(r'Suricata alert: .+?\(severity \d+, (.+?)\)\.')

SOURCE = "kb_v2"


@functools.lru_cache(maxsize=1)
def _get_reranker(model_name: str):
    from sentence_transformers import CrossEncoder
    return CrossEncoder(model_name)


def _record_to_doc(record) -> Document:
    payload = record.payload or {}
    text    = payload.get("text", "")
    meta    = dict(payload.get("metadata", {}))
    for k in ("chunk_id", "doc_id", "source", "kb_type"):
        meta.setdefault(k, payload.get(k, ""))
    return Document(page_content=text, metadata=meta)


def _kb_filter(kb_type: str, extra: list | None = None) -> Filter:
    must = [
        FieldCondition(key="metadata.source",  match=MatchValue(value=SOURCE)),
        FieldCondition(key="metadata.kb_type", match=MatchValue(value=kb_type)),
    ]
    if extra:
        must.extend(extra)
    return Filter(must=must)


def get_vectorstore() -> QdrantVectorStore:
    return QdrantVectorStore(
        client=build_client(),
        collection_name=settings.qdrant_collection,
        embedding=get_embeddings(),
        content_payload_key="text",
        metadata_payload_key="metadata",
    )


class KBRetriever(BaseRetriever):
    """Hybrid retriever for kb_v2.

    - port_profile / conn_state: exact filter match (no vector needed)
    - traffic_pattern / tactic:  semantic similarity search
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)

    vectorstore:    QdrantVectorStore
    qdrant_client:  QdrantClient
    collection:     str
    k_semantic:     int = 2
    reranker_model: str | None = "cross-encoder/ms-marco-MiniLM-L-6-v2"

    def _exact_fetch(self, kb_type: str, extra: list) -> list[Document]:
        records, _ = self.qdrant_client.scroll(
            collection_name=self.collection,
            scroll_filter=_kb_filter(kb_type, extra),
            limit=1,
            with_payload=True,
        )
        return [_record_to_doc(r) for r in records]

    def _semantic_fetch(self, query: str, kb_type: str) -> list[Document]:
        return self.vectorstore.similarity_search(
            query,
            k=self.k_semantic,
            filter=_kb_filter(kb_type),
        )

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        port_m  = _PORT_RE.search(query)
        state_m = _STATE_RE.search(query)
        cat_m   = _CAT_RE.search(query)
        dest_port  = int(port_m.group(1))  if port_m  else None
        conn_state = state_m.group(1)       if state_m else None
        category   = cat_m.group(1)         if cat_m   else None

        docs: list[Document] = []
        seen: set[str] = set()

        def add(d: Document) -> None:
            uid = d.metadata.get("chunk_id") or d.page_content[:40]
            if uid not in seen:
                seen.add(uid)
                docs.append(d)

        if dest_port is not None:
            for d in self._exact_fetch("port_profile", [
                FieldCondition(key="port", match=MatchValue(value=dest_port))
            ]):
                add(d)

        if conn_state:
            for d in self._exact_fetch("conn_state", [
                FieldCondition(key="state_code", match=MatchValue(value=conn_state))
            ]):
                add(d)

        if category:
            for d in self._exact_fetch("suricata_category", [
                FieldCondition(key="category", match=MatchValue(value=category))
            ]):
                add(d)

        for d in self._semantic_fetch(query, "traffic_pattern"):
            add(d)

        for d in self._semantic_fetch(query, "tactic"):
            add(d)

        if not self.reranker_model or len(docs) <= 1:
            return docs

        reranker = _get_reranker(self.reranker_model)
        scores   = reranker.predict([(query, d.page_content) for d in docs])
        ranked   = sorted(zip(scores, docs), key=lambda x: x[0], reverse=True)
        for score, d in ranked:
            d.metadata["rerank_score"] = float(score)
        return [d for _, d in ranked]


def build_retriever(k: int = 5) -> BaseRetriever:
    client = build_client()
    vs = QdrantVectorStore(
        client=client,
        collection_name=settings.qdrant_collection,
        embedding=get_embeddings(),
        content_payload_key="text",
        metadata_payload_key="metadata",
    )
    return KBRetriever(
        vectorstore=vs,
        qdrant_client=client,
        collection=settings.qdrant_collection,
        k_semantic=k // 2 or 2,
    )
