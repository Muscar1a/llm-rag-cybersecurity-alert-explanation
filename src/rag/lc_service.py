import json
import re
from .lc_chain import build_chat_chain, clear_session, get_session_history

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
        
        
class ChatService:
    def chat(
        self, 
        session_id: str, 
        message: str, 
        source: str | None = None,
        k: int = 5,
        template_name: str = "basic", 
    ):
        chain = build_chat_chain(source=source, k=k, template_name=template_name)
        result = chain.invoke(
            {"input": message},
            config={"configurable": {"session_id": session_id}},
        )
        return {
            **_parse_output(result["answer"]),
            "session_id":            session_id,
            "retrieved_context_ids": [
                doc.metadata.get("chunk_id") or doc.metadata.get("_id", "")
                for doc in result.get("context", [])
            ],
        }
        
    def get_history(self, session_id: str) -> list[dict]:
        return [
            {"role": "human" if m.type == "human" else "ai", "content": m.content}
            for m in get_session_history(session_id).messages
        ]
        
    def clear(self, session_id: str) -> None:
        clear_session(session_id)