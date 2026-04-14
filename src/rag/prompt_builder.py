


def build_prompt(alert_text: str, contexts: list[dict]) -> str:
    context_text = "\n\n".join(
        [f"[{i+1}] ({c['source']}/{c['doc_id']}) {c['text']}" for i, c in enumerate(contexts)]
    )
    return f"""
        You are a cybersecurity analyst.

        Alert:
        {alert_text}

        Retrieved knowledge:
        {context_text}

        Return strict JSON with keys:
        - threat_description
        - severity (Low|Medium|High)
        - rationale
        - mitigation_steps (array of strings)
        """.strip()
        
        