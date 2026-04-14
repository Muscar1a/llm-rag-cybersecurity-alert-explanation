from qdrant_client import models
from src.rag.qdrant_store import build_client
from src.rag.settings import settings
from src.rag.embeddings import QueryEmbedder


class Retriever:
    def __init__(self):
        self.client = build_client()
        self.embedder = QueryEmbedder()
    
    def search(self, query: str, k: int=5, source: str | None=None):
        vector = self.embedder.encode_query(query)
        
        query_filter = None 
        if source:
            query_filter = models.Filter(
                must=[
                    models.FieldCondition(
                        key="source",
                        match=models.MatchValue(value=source)
                    )
                ]
            )
            
        hits = self.client.search(
            collection_name=settings.qdrandt_collection,
            query_vector=vector,
            query_filter=query_filter,
            limit=k,
            with_payload=True
        )
        
        out = []
        for h in hits:
            p = h.payload or {}
            out.append({
                "chunk_id": p.get("chunk_id", ""),
                "doc_id": p.get("doc_id", ""),
                "source": p.get("source", ""),
                "text": p.get("text", ""),
                "metadata": p.get("metadata", {}),
                "score": float(h.score),
            })
        return out