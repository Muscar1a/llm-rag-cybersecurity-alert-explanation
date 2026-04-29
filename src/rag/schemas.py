from pydantic import BaseModel, Field
from typing import Literal


class AnalyzeRequest(BaseModel):
    alert_text: str = Field(min_length=5)
    source: Literal["cve", "mitre"] | None = None
    k: int = Field(default=5, ge=1, le=20)
    

class RetrievedChunk(BaseModel):
    chunk_id: str
    doc_id: str
    source: str
    text: str
    score: float
    metadata: dict
    
class AnalyzeResponse(BaseModel):
    threat_description: str
    severity: str
    rationale: str
    mitigation_steps: list[str]
    retrieved_context_ids: list[str]
    contexts: list[RetrievedChunk]