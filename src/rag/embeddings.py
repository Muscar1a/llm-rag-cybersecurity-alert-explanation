from functools import lru_cache
from langchain_huggingface import HuggingFaceEmbeddings
from .settings import settings


class _E5Embeddings(HuggingFaceEmbeddings):
    """Wraps HuggingFaceEmbeddings to add the required e5 prefixes.

    intfloat/e5-* models require:
      - documents: "passage: <text>"
      - queries:   "query: <text>"
    Without these prefixes retrieval quality degrades noticeably.
    """

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return super().embed_documents([f"passage: {t}" for t in texts])

    def embed_query(self, text: str) -> list[float]:
        return super().embed_query(f"query: {text}")


@lru_cache(maxsize=1)
def get_embeddings() -> _E5Embeddings:
    return _E5Embeddings(
        model_name=settings.embedding_model,
        model_kwargs={"device": "cuda" if _cuda_available() else "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )


def _cuda_available() -> bool:
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False
