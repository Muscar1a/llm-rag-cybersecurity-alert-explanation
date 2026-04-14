import numpy as np
from sentence_transformers import SentenceTransformer
from src.rag.settings import settings

class QueryEmbedder:
    def __init__(self):
        self.model = SentenceTransformer(settings.embedding)
    
    def encode_query(self, text: str) -> list[float]:
        v = self.model.encode(
            [text],
            convert_to_numpy=True,
            normalize_embeddings=True,
        )[0]
        return v.astype(np.float32).tolist()