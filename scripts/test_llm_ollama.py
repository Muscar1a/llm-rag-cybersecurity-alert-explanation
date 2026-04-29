import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.rag.llm_ollama import OllamaLLM

llm = OllamaLLM()


samples = [
    '{"threat_description":"test","severity":"Low","rationale":"ok","mitigation_steps":["a"]}',
    '<answer>{"threat_description":"test","severity":"Medium","rationale":"ok","mitigation_steps":["a","b"]}</answer>',
    '```json\n{"threat_description":"test","severity":"High","rationale":"ok","mitigation_steps":["x"]}\n```'
]

for s in samples:
    print(llm._extract_json_text(s))