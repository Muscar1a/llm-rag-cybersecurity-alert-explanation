from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder, PromptTemplate

DOCUMENT_PROMPT = PromptTemplate(
    input_variables=["page_content", "source", "doc_id"],
    template="source={source} doc_id={doc_id}\n{page_content}",
)

DOCUMENT_SEPARATOR = "\n\n"

CONTEXTUALIZE_SYSTEM = (
    "Given the chat history and the latest user question which may reference "
    "prior context, reformulate the question as a self-contained question. "
    "Do NOT answer it. If it is already standalone, return it unchanged."
)

_OUTPUT_SCHEMA = """\
Output ONLY a valid JSON object. No markdown, no explanations, no extra text

{
    "threat_description": "Semeantic explanation of what attack/behavior this alert indicates - not a restatement of the raw alert text.",
    "severity": "Low | Medium | High | Unknown - Based on the threat description, how severe is this alert? If you can't determine, say Unknown.",
    "rationale": "Evidence from the alert and retrieved knowledge that justifies the severity.",
    "mitigation_steps":["actionable step 1", "actionable step 2", "..."] - List of actionable steps to mitigate the threat.
}    
"""

# == contextualize_prompt ======================================================

contextualize_prompt = ChatPromptTemplate.from_messages([
    ("system", CONTEXTUALIZE_SYSTEM),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}")
])

# == BASIC ======================================================================

_BASIC_SYSTEM = f"""\
You are a senior SOC analyst. An IDS has fired an alert and your job is to \
explain its security significance to a Tier-1 analyst who need to decide \
whether to escalate.

Rules:
- threat_description must explain WHAT the alert means, not repeat its raw text.
- Use retrieved knowledge (CVE, MITRE ATT&CK, Sigma) to support your analysis.
- Do not invent CVE IDs, techniques IDs, or details absent from the alert or context.
- If retrieved knowledge is insufficient, state that clearly in rationale.
- severity must be exactly one of: Low, Medium, High, Unknown. Base this on the threat_description and rationale. If you can't determine, say Unknown.
- mitigation_steps must be 2-5 short actionable strings.

{_OUTPUT_SCHEMA}

Alert:
{{input}}

Retrieved Knowledge:
{{context}}"""

basic_prompt = ChatPromptTemplate.from_messages([
    ("system", _BASIC_SYSTEM),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])


# == CoT ==========================================================================

_COT_SYSTEM = f"""\
You are a senior SOC analyst explaining an IDS alert.

Think step by step:
1. What network behavior or attack pattern this alert indicate?
2. Which retrieved facts (CVE, MITRE ATT&CK, Sigma rules) are relevant?
3. What severity is justified by the combined evidence?
4. What concrete mitigation steps should the analyst take?

After reasoning, wrap your final answer in <answer> tags.

<answer>
{_OUTPUT_SCHEMA}
</answer>

Alert:
{{input}}

Retrieved Knowledge:
{{context}}"""

cot_prompt = ChatPromptTemplate.from_messages([
    ("system", _COT_SYSTEM),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])


# == Few-shot ==========================================================================

_EXAMPLE_ALERT = (
    "ET SCAN Nmap Scripting Engine User-Agent Detected — "
    "src=10.0.0.42:54321 dst=192.168.1.1:80"
)
_EXAMPLE_CONTEXT = """\
[source=sigma | doc_id=proc_creation_win_nmap]
Detects Nmap usage via its default user-agent string. Commonly used for reconnaissance.

[source=mitre | doc_id=T1046]
Network Service Discovery: Adversaries may attempt to get a listing of services \
running on remote hosts to identify attack surface."""
_EXAMPLE_OUTPUT = """\
{
"threat_description": "The alert indicates active network reconnaissance using Nmap. The source host
is scanning the target to enumerate open ports and services — a typical pre-exploitation step.",
"severity": "Medium",
"rationale": "Nmap scanning maps to T1046 (Network Service Discovery). The Sigma rule confirms the
user-agent fingerprint. Scanning alone is not an exploit but signals intent and warrants
investigation.",
"mitigation_steps": [
    "Block or isolate source IP 10.0.0.42 pending investigation.",
    "Verify whether 10.0.0.42 is an authorized scanner.",
    "Review firewall rules to limit unnecessary port exposure.",
    "Monitor for follow-on exploitation attempts from the same source."
]
}"""

FEW_SHOT_SYSTEM = f"""\
You are a senior SOC analyst explaining an IDS alert.
Follow the example format exactly. Output only the JSON object, no markdown or explanations.
Do not invent unsupported facts.

--- EXAMPLE ---
Alert:
{_EXAMPLE_ALERT}

Context:
{_EXAMPLE_CONTEXT}

Output:
{_EXAMPLE_OUTPUT}

Alert:
{{input}}

Retrieved Knowledge:
{{context}}"""

few_shot_prompt = ChatPromptTemplate.from_messages([
    ("system", FEW_SHOT_SYSTEM),
    MessagesPlaceholder("chat_history"),
    ("human", "{input}"),
])


# == Prompt selector ==========================================================================

PROMPTS = {
    "basic": basic_prompt,
    "cot": cot_prompt,
    "few_shot": few_shot_prompt,
}


def get_qa_prompt(template_name: str="basic") -> ChatPromptTemplate:
    if template_name not in PROMPTS:
        raise ValueError(f"Unknown template '{template_name}'. Choose from {list(PROMPTS)}")
    return PROMPTS[template_name]
