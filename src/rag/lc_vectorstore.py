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

_DEFAULT_SOURCE_K = {"nvd": 2, "mitre_attck": 2, "sigma": 1}


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
    source_k: dict[str, int] = Field(default_factory=lambda: dict(_DEFAULT_SOURCE_K))
    lambda_mult: float = 0.5
    fetch_k_mult: int = 10
    min_score: float = 0.82

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        docs: list[Document] = []
        seen: set[str] = set()

        for source, k in self.source_k.items():
            results = self.vectorstore.max_marginal_relevance_search(
                query,
                k=k,
                fetch_k=k * self.fetch_k_mult,
                lambda_mult=self.lambda_mult,
                score_threshold=self.min_score,
                filter=Filter(must=[
                    FieldCondition(key="metadata.source", match=MatchValue(value=source))
                ]),
            )
            
            for doc in results:
                uid = doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
                if uid not in seen:
                    seen.add(uid)
                    docs.append(doc)

        return docs


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

    return BalancedRetriever(vectorstore=get_vectorstore())
