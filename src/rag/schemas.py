from pydantic import BaseModel, Field


class AlertMetadata(BaseModel):
    src_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    conn_state: str | None = None
    label_tactic: str | None = None
    signature: str | None = None
    severity: int | str | None = None


class AnalyzeRequest(BaseModel):
    alert_text: str = Field(min_length=5)
    k: int = Field(default=5, ge=1, le=20)
    metadata: AlertMetadata | None = None
    auto_response: bool | None = None


class RemediationCommand(BaseModel):
    description: str
    command: str
    undo_command: str | None = None
    platform: str = "linux"
    risk: str = "low"
    auto_executable: bool = False
    executed: bool = False
    execution_status: str | None = None


class RetrievedChunk(BaseModel):
    chunk_id: str
    doc_id: str
    source: str
    text: str
    score: float = 0.0
    metadata: dict


class AnalyzeResponse(BaseModel):
    threat_description: str
    severity: str
    rationale: str
    mitigation_steps: list[str]
    retrieved_context_ids: list[str]
    contexts: list[RetrievedChunk] = Field(default_factory=list)
    remediation_commands: list[RemediationCommand] = Field(default_factory=list)
    auto_response_triggered: bool = False
    auto_response_log: list[str] = Field(default_factory=list)
    

