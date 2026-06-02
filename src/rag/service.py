import json
import re
from langchain_core.callbacks import BaseCallbackHandler
from .lc_chain import build_analyze_chain


def _get_llm_metrics():
    try:
        from src.api.middleware import LLM_TOKENS_PER_SECOND, LLM_TOKENS_GENERATED
        return LLM_TOKENS_PER_SECOND, LLM_TOKENS_GENERATED
    except Exception:
        return None, None


class _OllamaMetaCB(BaseCallbackHandler):
    """Captures Ollama response metadata (token counts, durations)."""
    def __init__(self):
        self.metadata = {}

    def on_llm_end(self, response, **kwargs):
        if response.generations and response.generations[0]:
            try:
                self.metadata.update(
                    response.generations[0][0].message.response_metadata
                )
            except Exception:
                pass


def _extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    if m := re.search(r"<answer>\s*(\{.*?\})\s*</answer>", text, re.DOTALL):
        return m.group(1).strip()
    if m := re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL):
        return m.group(1).strip()
    if m := re.search(r"\{.*\}", text, re.DOTALL):
        return m.group(0).strip()
    raise ValueError("No JSON found in model output.")


def _normalize(data: dict) -> dict:
    steps = data.get("mitigation_steps", [])
    if not isinstance(steps, list):
        steps = [str(steps)] if steps else []
    return {
        "threat_description": str(data.get("threat_description", "")),
        "severity":           str(data.get("severity", "Unknown")),
        "rationale":          str(data.get("rationale", "")),
        "mitigation_steps":   [str(s) for s in steps],
    }


def _parse_output(raw: str) -> dict:
    try:
        return _normalize(json.loads(_extract_json(raw)))
    except Exception as e:
        return {
            "threat_description": raw,
            "severity":           "Unknown",
            "rationale":          f"Could not parse model output: {e}",
            "mitigation_steps":   [],
        }


def _doc_to_chunk(doc) -> dict:
    meta = doc.metadata
    return {
        "chunk_id": meta.get("chunk_id", ""),
        "doc_id":   meta.get("doc_id", meta.get("id", "")),
        "source":   meta.get("source", "unknown"),
        "text":     doc.page_content,
        "score":    float(meta.get("rerank_score", 0.0)),
        "metadata": {k: v for k, v in meta.items() if k != "rerank_score"},
    }


class RagService:
    def stream_analyze(
        self,
        alert_text: str,
        k: int = 5,
        source: str | None = None,
        template_name: str = "basic",
    ):
        """Generator yielding SSE-style dicts: contexts → tokens → done."""
        chain = build_analyze_chain(source=source, k=k, template_name=template_name)

        raw_docs = []
        contexts_sent = False
        full_answer = ""

        for chunk in chain.stream({"input": alert_text}):
            if "context" in chunk and not contexts_sent:
                raw_docs = chunk["context"]
                contexts_sent = True
                yield {
                    "type": "contexts",
                    "contexts": [_doc_to_chunk(d) for d in raw_docs],
                }
            if chunk.get("answer"):
                full_answer += chunk["answer"]
                yield {"type": "token", "token": chunk["answer"]}

        yield {"type": "done", **_parse_output(full_answer)}


    def analyze(
        self,
        alert_text: str,
        k: int = 5,
        source: str | None = None,
        template_name: str = "basic",
    ) -> dict:
        cb = _OllamaMetaCB()
        chain = build_analyze_chain(source=source, k=k, template_name=template_name)
        result = chain.invoke({"input": alert_text}, config={"callbacks": [cb]})

        # Record LLM speed metrics from Ollama response metadata
        tok_hist, tok_counter = _get_llm_metrics()
        eval_count = cb.metadata.get("eval_count", 0)
        eval_duration_ns = cb.metadata.get("eval_duration", 0)
        if tok_hist and eval_count and eval_duration_ns:
            tokens_per_sec = eval_count / (eval_duration_ns / 1e9)
            tok_hist.observe(tokens_per_sec)
            tok_counter.inc(eval_count)

        raw_docs = result.get("context", [])
        return {
            **_parse_output(result["answer"]),
            "retrieved_context_ids":   [
                doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
                for doc in raw_docs
            ],
            "retrieved_contexts_text": [doc.page_content for doc in raw_docs],
            "contexts":                [_doc_to_chunk(doc) for doc in raw_docs],
            "llm_metadata":            cb.metadata,
        }
