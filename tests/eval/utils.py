from functools import lru_cache
import sys
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_openai import ChatOpenAI
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
    
@lru_cache(maxsize=1)
def get_judge_llm():
    from src.rag.settings import settings
    return ChatOpenAI(
        model=settings.deepseek_model,
        api_key=settings.deepseek_api_key,
        base_url="https://api.deepseek.com",
        temperature=0,
    )

@lru_cache(maxsize=1)
def get_judge_emb():
    from src.rag.settings import settings
    return HuggingFaceEmbeddings(
        model_name=settings.embedding_model,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )

def safe_val(val, default=None):
    import math
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return default
    return round(val, 3)

def _is_rate_limit(e: Exception) -> bool:
    return "429" in str(e) or "rate_limit" in str(e).lower() or "too many" in str(e).lower()
