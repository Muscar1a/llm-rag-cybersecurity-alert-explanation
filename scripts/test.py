import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from src.rag.prompt_builder import build_prompt

contexts = [
    {
        "source": "mitre",
        "doc_id": "T1110",
        "text": "Brute Force involves repeated attempts to guess credentials."
    },
    {
        "source": "mitre",
        "doc_id": "T1021",
        "text": "Remote Services may be used for lateral movement."
    }
]

prompt = build_prompt(
    alert_text="Multiple failed logins followed by suspicious remote access.",
    contexts=contexts,
    template_name="cot",
)

print(prompt)