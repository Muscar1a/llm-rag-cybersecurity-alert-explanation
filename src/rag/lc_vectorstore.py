from langchain_qdrant import QdrantVectorStore
from langchain_core.vectorstores import VectorStoreRetriever
from qdrant_client.models import Filter, FieldCondition, MatchValue
from .qdrant_store import build_client
from .embeddings import get_embeddings
from .settings import settings


def get_vectorstore() -> QdrantVectorStore:
    return QdrantVectorStore(
        client=build_client(),
        collection_name=settings.qdrant_collection,
        embedding=get_embeddings(),
        content_payload_key="text",
        metadata_payload_key="metadata",
    )
    

def build_retriever(source: str | None=None, k: int=5) -> VectorStoreRetriever:
    search_kwargs: dict = {"k": k}
    
    if source:
        search_kwargs["filter"] = Filter(
            must=[FieldCondition(key="source", match=MatchValue(value=source))]
        )
        
    return get_vectorstore().as_retriever(
        search_type="similarity",
        search_kwargs=search_kwargs,
    )