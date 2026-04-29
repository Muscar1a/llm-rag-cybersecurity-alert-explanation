import json
from ollama import Client
from .settings import settings
import re

class OllamaLLM:
    def __init__(self):
        self.client = Client(host=settings.ollama_host)
        self.model_name = self._resolve_model_name()

    def _list_installed_models(self) -> list[str]:
        try:
            resp = self.client.list()
        except Exception as e:
            raise RuntimeError(
                f"Could not contact Ollama at {settings.ollama_host}: {e}"
            ) from e

        models = getattr(resp, "models", None)
        if models is None and isinstance(resp, dict):
            models = resp.get("models", [])

        names = []
        for model in models or []:
            if isinstance(model, dict):
                name = model.get("model") or model.get("name")
            else:
                name = getattr(model, "model", None) or getattr(model, "name", None)
            if name:
                names.append(str(name))
        return names

    def _resolve_model_name(self) -> str:
        installed = self._list_installed_models()
        configured = (settings.ollama_model or "").strip()
        recommended = "qwen2.5:3b-instruct"

        if configured:
            if configured in installed:
                return configured
            if not installed:
                raise RuntimeError(
                    f"Ollama model '{configured}' is not installed, and no local models were found. "
                    f"Run `ollama pull {recommended}` and set OLLAMA_MODEL={recommended} in .env."
                )
            raise RuntimeError(
                f"Ollama model '{configured}' is not installed. Available local models: {', '.join(installed)}"
            )

        if installed:
            return installed[0]

        raise RuntimeError(
            f"No local Ollama models found. Run `ollama pull {recommended}` "
            f"and set OLLAMA_MODEL={recommended} in .env."
        )

    def _extract_json_text(self, text: str) -> str:
        text = text.strip()
        
        if text.startswith("{") and text.endswith("}"):
            return text
        
        tag_match = re.search(r"<answer>\s*(\{.*?\})\s*</answer>", text, re.DOTALL)
        if tag_match:
            return tag_match.group(1).strip()  
        
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence_match:
            return fence_match.group(1).strip()
        
        obj_match = re.search(r"\{.*\}", text, re.DOTALL)
        if obj_match:
            return obj_match.group(0).strip()

        raise ValueError("No JSON object found in the model output.")
    
    def _normalize_output(self, data: dict) -> dict:
        steps = data.get("mitigation_steps", [])
        if not isinstance(steps, list):
            steps = [str(steps)] if steps else []
        
        steps = [str(x) for x in steps]
        return {
            "threat_description": str(data.get("threat_description", "")),
            "severity": str(data.get("severity", "Unknown")),
            "rationale": str(data.get("rationale", "")),
            "mitigation_steps": steps,
        }
        
    def generate(self, prompt: str) -> dict:
        resp = self.client.generate(
            model=self.model_name,
            prompt=prompt,
            options={"temperature": 0.1},
        )
        text = resp.get("response", "").strip()

        try:
            json_text = self._extract_json_text(text)
            data = json.loads(json_text)
            return self._normalize_output(data)
        except Exception as e:
            return {
                "threat_description": text,
                "severity": "Unknown",
                "rationale": f"Model output could not be parsed as valid JSON: {e}",
                "mitigation_steps": [],
            }
