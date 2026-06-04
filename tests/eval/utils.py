import time
from functools import lru_cache
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
import os

SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3, "Unknown": -1}
SEVERITY_MIN = {
    "Credential_Access":    "High",
    "Exfiltration":         "High",
    "Initial_Access":       "High",
    "Privilege_Escalation": "High",
    "Defense_Evasion":      "Medium",
    "Persistence":          "Medium",
    "Reconnaissance":       "Low",
}

HALLUCINATION_PATTERNS = [
    ("SYN flood: NOT possible", "syn flood"),
    ("Zero-byte flow",          "exfiltrat"),
    ("server did not respond",  "established connection"),
]


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


def get_severity_verdict(output_sev: str, label: str) -> str:
    expected_min = SEVERITY_MIN.get(label)
    if not expected_min: return "unknown_label"
    out_rank = SEVERITY_ORDER.get(output_sev, -1)
    if out_rank == -1: return "unknown_severity"
    min_rank = SEVERITY_ORDER[expected_min]
    if out_rank < min_rank: return "underestimated"
    if out_rank > min_rank: return "overestimated"
    return "correct"

def get_hallucination_pattern_hit(alert_text: str, output_text: str) -> bool:
    alert_lower = alert_text.lower()
    output_lower = output_text.lower()
    return any(cond in alert_lower and viol in output_lower for cond, viol in HALLUCINATION_PATTERNS)

def get_context_diversity(context_ids: list) -> str:
    has_mitre = any(cid.startswith("T")   for cid in context_ids)
    has_sigma = any("sigma" in cid        for cid in context_ids)
    has_et    = any("et_rule" in cid      for cid in context_ids)
    parts = [s for s, flag in [("mitre", has_mitre), ("sigma", has_sigma), ("et", has_et)] if flag]
    return "+".join(parts) if parts else "none"

_BACKOFF_BASE = 5  # seconds; doubles each retry on 429 → 5s, 10s, 20s

def _is_rate_limit(e: Exception) -> bool:
    return "429" in str(e) or "rate_limit" in str(e).lower() or "too many" in str(e).lower()

def judge_attack_type(label: str, output_text: str) -> bool:
    prompt = (
        f"You are an elite SOC expert. Read the threat analysis report below and answer with only True or False:\n"
        f"Does the report correctly analyze and identify signs of a [{label}] attack?\n\n"
        f"Report:\n{output_text}"
    )
    for attempt in range(5):
        try:
            llm = get_judge_llm()
            response = llm.invoke([HumanMessage(content=prompt)])
            return response.content.strip().lower().startswith("true")
        except Exception as e:
            if attempt == 4:
                return False
            wait = _BACKOFF_BASE * (2 ** attempt) if _is_rate_limit(e) else 5
            print(f"  [judge_attack_type] attempt {attempt+1} failed ({e}), retrying in {wait}s...")
            time.sleep(wait)
    return False
