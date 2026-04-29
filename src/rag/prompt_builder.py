from typing import List, Dict

def format_contexts(contexts: List[Dict]) -> str:
    if not contexts:
        return "No retrieved knowledge available."
    
    lines = []
    for i, c in enumerate(contexts, 1):
        source = c.get("source", "")
        doc_id = c.get("doc_id", "")
        text = c.get("text", "").strip()
        lines.append(f"[{i}] source={source} doc_id={doc_id}\n{text}")
    return "\n\n".join(lines)


def build_prompt(alert_text: str, contexts: List[Dict], template_name: str="basic") -> str:
    context_text = format_contexts(contexts)
    
    if template_name == "basic":
        return build_basic_prompt(alert_text, context_text)
    elif template_name == "cot":
        return build_cot_prompt(alert_text, context_text)
    elif template_name == "few_shot":
        return build_few_shot_prompt(alert_text, context_text)
    
    raise ValueError(f"Unknown template_name: {template_name}")


def build_basic_prompt(alert_text: str, context_text: str) -> str:
    return f"""
You are a senior cybersecurity analyst.

Your task is to analyze the alert and produce a concise security assessment.

Instructions:
- Use the retrieved knowledge when it is relevant.
- Do not invent CVE IDs, MITRE technique IDs, products, versions, or attack details that are not supported by the alert or retrieved knowledge.
- If the evidence is insufficient, say so briefly in the rationale.
- Severity must be exactly one of: Low, Medium, High, Unknown.
- mitigation_steps must be a JSON array of short strings.
- Output JSON only. Do not include markdown, explanation, or extra text.

Required JSON schema:
{{
  "threat_description": "string",
  "severity": "Low|Medium|High|Unknown",
  "rationale": "string",
  "mitigation_steps": ["string", "string"]
}}

Alert:
{alert_text}

Retrieved Knowledge:
{context_text}
""".strip()


def build_cot_prompt(alert_text: str, context_text: str) -> str:
    return f"""
You are a senior cybersecurity analyst.

Think through the following questions step by step before producing your final answer:
1. What suspicious behavior does the alert indicate?
2. Which retrieved facts are relevant?
3. What severity is justified by the evidence?
4. What mitigation steps are appropriate?

After your reasoning, output your final answer as a JSON block inside <answer> tags.

Rules:
- Do not invent unsupported facts.
- If evidence is limited, say so in the rationale.
- Severity must be exactly one of: Low, Medium, High, Unknown.
- mitigation_steps must be a JSON array of 2-5 short actionable strings.

<answer>
{{
  "threat_description": "string",
  "severity": "Low|Medium|High|Unknown",
  "rationale": "string",
  "mitigation_steps": ["step 1", "step 2"]
}}
</answer>

Alert:
{alert_text}

Retrieved knowledge:
{context_text}
""".strip()


def build_few_shot_prompt(alert_text: str, context_text: str) -> str:
    example_alert = "Multiple failed logins followed by a successful remote desktop login from an unusual internal host."
    example_context = """[1] source=mitre doc_id=T1021
Remote Services may be used for lateral movement.

[2] source=mitre doc_id=T1110
Brute Force involves repeated attempts to guess credentials."""
    example_output = """
{
  "threat_description": "The alert suggests possible brute-force activity followed by suspicious remote access that may indicate lateral movement.",
  "severity": "High",
  "rationale": "The sequence of repeated failed logins and a later successful remote desktop login is consistent with credential attack behavior and possible follow-on movement. MITRE knowledge about Brute Force and Remote Services supports this interpretation.",
  "mitigation_steps": [
    "Investigate the source and destination hosts involved in the login activity.",
    "Reset or disable potentially compromised accounts.",
    "Review remote access policies and restrict unnecessary RDP access."
  ]
}
""".strip()

    return f"""
You are a senior cybersecurity analyst.

Follow the example format exactly.
Use the retrieved knowledge when relevant.
Do not invent unsupported facts.
If evidence is insufficient, say so in the rationale.
Output JSON only.

Example Alert:
{example_alert}

Example Retrieved Knowledge:
{example_context}

Example Output:
{example_output}

Now analyze the real input below.

Required JSON schema:
{{
  "threat_description": "string",
  "severity": "Low|Medium|High|Unknown",
  "rationale": "string",
  "mitigation_steps": ["string", "string"]
}}

Alert:
{alert_text}

Retrieved knowledge:
{context_text}
""".strip()