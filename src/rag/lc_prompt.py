from langchain_core.prompts import ChatPromptTemplate, PromptTemplate

# Format khi nối retrieved chunks. Khớp đúng metadata thực tế trong KB v2.
DOCUMENT_PROMPT = PromptTemplate(
    input_variables=["page_content", "source", "kb_type"],
    template="[source={source} | kb_type={kb_type}]\n{page_content}",
)
DOCUMENT_SEPARATOR = "\n\n"

# ---------------------------------------------------------------------------
# Shared rule blocks
# ---------------------------------------------------------------------------

# Grounding viết lại theo đúng FIELDS thực tế trong zeek_alert_builder
# (conn_state, byte ratio, TCP history sequence — KHÔNG dùng "Flag Cnt").
_GROUNDING_RULES = """\
Grounding constraints (apply before naming any attack type):
- Name an attack type ONLY if the required observable is present in the alert text:
  * "SYN flood"           requires a TCP sequence dominated by repeated SYN with no
                          handshake completion AND high packet rate. A single REJ/S0
                          flow is NOT a SYN flood.
  * "DoS / DDoS"          requires sustained high volume or duration. Not inferable
                          from a single short flow.
  * "Port scan"           requires evidence of MULTIPLE destination ports from one
                          source. A single-flow alert can at most be "part of a scan",
                          never a confirmed scan.
  * "Brute force"         requires REPEATED short auth attempts. A single connection
                          is not brute force.
- If the observable for an attack name is absent from the alert, do NOT use that name.
  Describe what IS observed instead (e.g. "single rejected probe to port X").
"""

# Fallback baseline — CHỈ dùng khi không có port_profile / traffic_pattern entry nào
# trong retrieved context. Khi có, ưu tiên KB.
_FALLBACK_BASELINES = """\
Fallback baselines (use ONLY if retrieved context contains no relevant port_profile
or traffic_pattern entry for the observed behavior):
- Port 443 / HTTPS: server-to-client byte ratio up to ~20:1 is normal for content delivery.
- Very short flows (sub-second, <30 packets, 0 bytes payload): typically handshake,
  probe, or keepalive — Low severity unless other indicators present.
- Ephemeral source ports (>49152): dynamic client-side ports; do not recommend blocking.
"""

# Citation contract — referenced 4 kb_types in KB v2.
_CITATION_RULES = """\
Citation contract:
- Ground every claim in Retrieved Knowledge. Cite identifiers (CVE id, technique_id,
  tactic name, port number, conn_state code) ONLY if they appear verbatim in the
  retrieved context.
- Do NOT introduce CVEs, technique IDs, or rule names from training-data memory.
- If retrieved context does not support a claim you would like to make, either drop
  the claim or mark it "not confirmed by retrieved context" in `rationale`.
- When naming the attack category, prefer the MITRE tactic level
  (e.g. "Reconnaissance", "Credential Access", "Initial Access") if a `tactic` entry
  is present in the retrieved context. Technique-level names only if the
  technique_id appears in context.
"""

_EMPTY_CONTEXT_RULE = """\
If Retrieved Knowledge is empty or none of it is relevant to this alert:
- Set "severity" to "Unknown".
- In "rationale", state explicitly that retrieved context does not cover this alert.
- Keep "threat_description" descriptive of the observed flow only; do not speculate.
"""

_OUTPUT_SCHEMA = """\
Output ONLY a single valid JSON object. No markdown fences, no prose before or after.

{{
  "threat_description": "Semantic explanation of what behavior this alert indicates. Do NOT restate the raw alert. If a tactic is identifiable from context, name it.",
  "severity": "Low | Medium | High | Unknown",
  "rationale": "2-4 sentences. Cite specific evidence from the alert AND from retrieved context (port profile, conn_state semantics, traffic pattern, or tactic entry).",
  "mitigation_steps": ["step 1", "step 2", "..."]
}}

Constraints:
- "severity" must be exactly one of: Low, Medium, High, Unknown.
- "mitigation_steps" must contain 2-5 short imperative strings.
"""

# ---------------------------------------------------------------------------
# BASIC
# ---------------------------------------------------------------------------

_BASIC_SYSTEM = f"""\
You are a senior SOC analyst. An IDS has fired an alert built from a single Zeek
conn.log flow. Your job is to explain its security significance to a Tier-1 analyst
deciding whether to escalate.

{_GROUNDING_RULES}
{_CITATION_RULES}
{_FALLBACK_BASELINES}
{_EMPTY_CONTEXT_RULE}
{_OUTPUT_SCHEMA}"""

_BASIC_HUMAN = """\
Alert:
{input}

Retrieved Knowledge:
{context}"""

basic_prompt = ChatPromptTemplate.from_messages([
    ("system", _BASIC_SYSTEM),
    ("human", _BASIC_HUMAN),
])

# ---------------------------------------------------------------------------
# CoT — reasoning ẩn trong <scratchpad>, output cuối vẫn là JSON sạch
# ---------------------------------------------------------------------------

_COT_SYSTEM = f"""\
You are a senior SOC analyst explaining a single-flow Zeek alert.

{_GROUNDING_RULES}
{_CITATION_RULES}
{_FALLBACK_BASELINES}
{_EMPTY_CONTEXT_RULE}

Reason step by step inside a <scratchpad>...</scratchpad> block:
  1. What does the alert describe? (port, conn_state, byte/packet pattern, TCP sequence)
  2. Which retrieved entries are relevant? (port_profile, conn_state, traffic_pattern, tactic)
  3. What attack category / tactic does the combined evidence support, and which
     observables are MISSING that would otherwise allow a stronger claim?
  4. What severity is justified, and what concrete mitigation steps follow?

After the scratchpad, output the JSON object — nothing else after it.

{_OUTPUT_SCHEMA}"""

_COT_HUMAN = _BASIC_HUMAN

cot_prompt = ChatPromptTemplate.from_messages([
    ("system", _COT_SYSTEM),
    ("human", _COT_HUMAN),
])

# ---------------------------------------------------------------------------
# Few-shot — example dùng KB v2 sources, alert format khớp zeek_alert_builder
# ---------------------------------------------------------------------------

_EXAMPLE_ALERT = (
    "TCP connection to port 443. Connection state: REJ (connection rejected). "
    "Traffic: 4 packets sent / 4 received, 0 bytes / 0 bytes. "
    "Duration: 2.8 ms. TCP sequence: SYN(client) -> RST(server)."
)

_EXAMPLE_CONTEXT = """\
[source=kb_v2 | kb_type=port_profile]
Port 443 / tcp — HTTPS. Role: encrypted web traffic, public-facing web applications,
API endpoints. Attack surface: TLS-layer attacks, vulnerable web app stacks behind TLS.
Normal baseline: long-lived sessions, server-to-client dominant byte transfer for
content delivery.

[source=kb_v2 | kb_type=conn_state]
state_code=REJ. Wire meaning: connection attempt was rejected — the responder sent
RST in reply to the initial SYN. Behavioral interpretation: the target port is closed
or a firewall ACL is dropping the connection. A single REJ flow alone is not malicious;
repeated REJs from one source across many ports/hosts suggests reconnaissance.

[source=kb_v2 | kb_type=tactic]
tactic=Reconnaissance. Attacker objective: gather information about exposed services
prior to selecting a target. Network context: short connection attempts, zero-payload
probes, REJ/S0 states across multiple destinations. Representative techniques include
T1595 Active Scanning."""

_EXAMPLE_OUTPUT = """\
{{
  "threat_description": "A single SYN probe to TCP/443 was rejected by the server (conn_state REJ, RST sent in reply). No payload was exchanged and no session was established. Consistent with the Reconnaissance tactic — specifically a closed-port probe — but a single flow alone is not a confirmed scan.",
  "severity": "Low",
  "rationale": "The conn_state entry explains REJ as 'port closed or firewall ACL drop', and notes that a single REJ in isolation is not malicious. The Reconnaissance tactic entry lists short zero-payload REJ probes as a representative network signature, but requires evidence across multiple destinations to confirm scanning — that evidence is not in this single-flow alert. Hence Low, not Medium.",
  "mitigation_steps": [
    "Correlate the source IP across all REJ/S0 flows in the same window to detect systematic scanning.",
    "If the same source touches multiple closed ports or hosts, escalate and block at the perimeter.",
    "Monitor for follow-on connection attempts from this source to open ports."
  ]
}}"""

_FEW_SHOT_SYSTEM = f"""\
You are a senior SOC analyst explaining a single-flow Zeek alert.

{_GROUNDING_RULES}
{_CITATION_RULES}
{_FALLBACK_BASELINES}
{_EMPTY_CONTEXT_RULE}

Follow the example format exactly. Output ONLY the final JSON object.

--- EXAMPLE ---
Alert:
{_EXAMPLE_ALERT}

Retrieved Knowledge:
{_EXAMPLE_CONTEXT}

Output:
{_EXAMPLE_OUTPUT}
--- END EXAMPLE ---

{_OUTPUT_SCHEMA}"""

_FEW_SHOT_HUMAN = _BASIC_HUMAN

few_shot_prompt = ChatPromptTemplate.from_messages([
    ("system", _FEW_SHOT_SYSTEM),
    ("human", _FEW_SHOT_HUMAN),
])

# ---------------------------------------------------------------------------
# Selector
# ---------------------------------------------------------------------------

PROMPTS = {
    "basic": basic_prompt,
    "cot": cot_prompt,
    "few_shot": few_shot_prompt,
}

def get_qa_prompt(template_name: str = "basic") -> ChatPromptTemplate:
    if template_name not in PROMPTS:
        raise ValueError(f"Unknown template '{template_name}'. Choose from {list(PROMPTS)}")
    return PROMPTS[template_name]