from functools import lru_cache
from langchain_huggingface import HuggingFaceEmbeddings
from .settings import settings

@lru_cache(maxsize=1)
def get_embeddings() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(
        model_name=settings.embedding_model,
        model_kwargs={"device": "cuda" if _cuda_available() else "cpu"},
        encode_kwargs={"normalize_embeddings": True}
    )
    
def _cuda_available() -> bool:
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False