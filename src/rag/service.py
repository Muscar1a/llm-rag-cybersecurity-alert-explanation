import json
import re
from langchain_core.callbacks import BaseCallbackHandler
from .lc_chain import build_analyze_chain
from .response_actions import ResponseActionEngine, detect_tactic, SEVERITY_RANK
from .settings import settings

def _get_llm_metrics():
    try:
        from src.api.middleware import LLM_TOKENS_PER_SECOND, LLM_TOKENS_GENERATED
        return LLM_TOKENS_PER_SECOND, LLM_TOKENS_GENERATED
    except Exception:
        return None, None


class _LLMMetaCB(BaseCallbackHandler):
    """Captures LLM response metadata (token counts, durations)."""
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


def _clean_bpe_artifacts(text: str) -> str:
    # GPT-2/Qwen tokenizers use Ġ (U+0120) for space and Ċ (U+010A) for newline
    return text.replace("Ġ", " ").replace("Ċ", "\n")


def _extract_json(text: str) -> str:
    text = _clean_bpe_artifacts(text)
    # Handle both closed <think>...</think> and unclosed <think>... (truncated output)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)
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


_engine = ResponseActionEngine()


class RagService:
    def _build_remediation(
        self,
        parsed: dict,
        raw_docs: list,
        metadata: dict | None,
        auto_response: bool | None,
    ) -> tuple[list[dict], bool, list[str]]:
        meta = metadata or {}
        tactic = detect_tactic(
            meta.get("label_tactic"),
            raw_docs,
            parsed,
        )
        commands = _engine.generate(
            severity=parsed["severity"],
            tactic=tactic,
            metadata=meta,
        )

        enabled = auto_response if auto_response is not None else settings.auto_response_enabled
        sev_rank = SEVERITY_RANK.get(parsed["severity"], 0)
        threshold_rank = SEVERITY_RANK.get(settings.auto_response_severity_threshold, 0)

        auto_triggered = False
        auto_log: list[str] = []
        if enabled and sev_rank >= threshold_rank:
            auto_log = _engine.execute(commands, mode=settings.auto_response_mode)
            auto_triggered = bool(auto_log)

        return commands, auto_triggered, auto_log

    def stream_analyze(
        self,
        alert_text: str,
        k: int = 5,
        template_name: str = "basic",
        metadata: dict | None = None,
        auto_response: bool | None = None,
        provider: str = "vllm",
        api_key: str | None = None,
        model: str | None = None,
    ):
        """Generator yielding SSE-style dicts: contexts → tokens → done."""
        chain = build_analyze_chain(
            k=k, template_name=template_name,
            provider=provider, api_key=api_key, model=model,
        )

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

        parsed = _parse_output(full_answer)
        commands, auto_triggered, auto_log = self._build_remediation(
            parsed, raw_docs, metadata, auto_response,
        )
        yield {
            "type": "done",
            **parsed,
            "remediation_commands": commands,
            "auto_response_triggered": auto_triggered,
            "auto_response_log": auto_log,
        }

    def analyze(
        self,
        alert_text: str,
        k: int = 5,
        template_name: str = "basic",
        metadata: dict | None = None,
        auto_response: bool | None = None,
        provider: str = "vllm",
        api_key: str | None = None,
        model: str | None = None,
    ) -> dict:
        cb = _LLMMetaCB()
        chain = build_analyze_chain(
            k=k, template_name=template_name,
            provider=provider, api_key=api_key, model=model,
        )
        result = chain.invoke({"input": alert_text}, config={"callbacks": [cb]})

        # Record LLM speed metrics from response metadata
        tok_hist, tok_counter = _get_llm_metrics()
        token_usage = cb.metadata.get("token_usage", {})
        completion_tokens = token_usage.get("completion_tokens", 0)
        if tok_hist and completion_tokens:
            total_time = cb.metadata.get("total_duration", 0)
            if total_time:
                tok_hist.observe(completion_tokens / total_time)
            tok_counter.inc(completion_tokens)

        raw_docs = result.get("context", [])
        parsed = _parse_output(result["answer"])
        commands, auto_triggered, auto_log = self._build_remediation(
            parsed, raw_docs, metadata, auto_response,
        )
        return {
            **parsed,
            "remediation_commands":    commands,
            "auto_response_triggered": auto_triggered,
            "auto_response_log":       auto_log,
            "retrieved_context_ids":   [
                doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
                for doc in raw_docs
            ],
            "retrieved_contexts_text": [doc.page_content for doc in raw_docs],
            "contexts":                [_doc_to_chunk(doc) for doc in raw_docs],
            "llm_metadata":            cb.metadata,
        }
