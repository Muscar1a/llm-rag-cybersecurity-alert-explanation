import json
from ollama import Client
from src.rag.settings import settings


class OllamaLLM:
    def __init__(self):
        self.client = Client(host=settings.ollama_host)

    def generate(self, prompt: str) -> dict:
        resp = self.client.generate(
            model=settings.ollama_model,
            prompt=prompt,
            options={"temperature": 0.1},
        )
        text = resp.get("response", "").strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "threat_description": text,
                "severity": "Unknown",
                "rationale": "Model output was not valid JSON, so severity could not be reliably classified.",
                "mitigation_steps": [],
            }
        except Exception as e:
            # Log the error and return fallback
            return {
                "threat_description": f"Error generating response: {str(e)}",
                "severity": "Unknown",
                "rationale": "LLM response processing failed before classification.",
                "mitigation_steps": [],
            }