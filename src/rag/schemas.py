from pydantic import BaseModel, Field
from typing import Literal
import uuid


class AnalyzeRequest(BaseModel):
    alert_text: str = Field(min_length=5)
    source: Literal["cve", "mitre", "sigma"] | None = None
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
    

class ChatRequest(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message: str = Field(min_length=1)
    source: Literal["cve", "mitre", "sigma"] | None = None
    k: int = Field(default=5, ge=1, le=20)
    template_name: Literal["basic", "cot", "few_shot"] = "basic"
    

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatResponse(BaseModel):
    threat_description: str
    severity: str
    rationale: str
    mitigation_steps: list[str]
    session_id: str
    retrieved_context_ids: list[str]
    
    
class ChatHistoryResponse(BaseModel):
    session_id: str
    messages: list[ChatMessage]