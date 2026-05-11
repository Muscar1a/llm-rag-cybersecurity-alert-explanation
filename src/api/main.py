from fastapi import FastAPI
from src.rag.schemas import AnalyzeRequest, AnalyzeResponse
from src.rag.service import RagService

from src.rag.lc_service import ChatService
from src.rag.schemas import (
    ChatRequest, ChatResponse,
    ChatMessage, ChatHistoryResponse,
)

app = FastAPI(title="Cyber RAG API", version="1.0")
rag = RagService()
chat_svc = ChatService()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    return rag.analyze(
        alert_text=request.alert_text,
        k=request.k,
        source=request.source,
    )
    

@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest):
    return chat_svc.chat(
        session_id=req.session_id,
        message=req.message,
        source=req.source,
        k=req.k,
        template_name=req.template_name,
    )
    

@app.get("/chat/{session_id}/history", response_model=ChatHistoryResponse)
def chat_history(session_id: str):
    return ChatHistoryResponse(
        session_id=session_id,
        messages=[ChatMessage(**m) for m in chat_svc.get_history(session_id)],
    )
    

@app.delete("/chat/{session_id}")
def clear_chat(session_id: str):
    chat_svc.clear(session_id)
    return {"cleared": session_id}