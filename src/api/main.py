from fastapi import FastAPI
from src.rag.schemas import AnalyzeRequest, AnalyzeResponse
from src.rag.service import RagService

app = FastAPI(title="Cyber RAG API", version="1.0")
rag = RagService()


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