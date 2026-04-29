from .retriever import Retriever
from .llm_ollama import OllamaLLM
from .prompt_builder import build_prompt

class RagService:
    def __init__(self):
        self.retriever = Retriever()
        self.llm = OllamaLLM()
        
    def analyze(self, alert_text: str, k: int, source: str | None):
        contexts = self.retriever.search(query=alert_text, k=k, source=source)
        prompt = build_prompt(
            alert_text=alert_text, 
            contexts=contexts,
            template_name="basic",
        )
        llm_out = self.llm.generate(prompt)
        
        return {
            "threat_description": llm_out.get("threat_description", ""),
            "severity": llm_out.get("severity", "Unknown"),
            "rationale": llm_out.get("rationale", ""),
            "mitigation_steps": llm_out.get("mitigation_steps", []),
            "retrieved_context_ids": [c["chunk_id"] for c in contexts],
            "contexts": contexts,
        }
