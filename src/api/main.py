import json
import os
import subprocess

import httpx
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from src.api.middleware import PrometheusMiddleware, metrics_app
from src.rag.schemas import AnalyzeRequest, AnalyzeResponse
from src.rag.service import RagService
from src.rag.settings import settings

app = FastAPI(title="Cyber RAG API", version="1.0")
app.add_middleware(PrometheusMiddleware)
app.mount("/metrics", metrics_app)
rag = RagService()


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return os.getenv("GIT_SHA", "unknown")


def _check_qdrant() -> bool:
    try:
        r = httpx.get(f"http://{settings.qdrant_host}:{settings.qdrant_port}/", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _check_ollama() -> bool:
    try:
        r = httpx.get(f"{settings.ollama_host}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


@app.get("/health")
def health():
    qdrant_ok = _check_qdrant()
    ollama_ok = _check_ollama()
    status = "ok" if (qdrant_ok and ollama_ok) else "degraded"
    return {
        "status": status,
        "qdrant": "ok" if qdrant_ok else "unreachable",
        "ollama": "ok" if ollama_ok else "unreachable",
    }


@app.get("/version")
def version():
    import yaml
    params = {}
    try:
        with open("params.yaml", "r", encoding="utf-8") as f:
            params = yaml.safe_load(f)
    except Exception:
        pass
    return {
        "git_sha": _git_sha(),
        "llm_model": params.get("llm", {}).get("model", settings.ollama_model),
        "embedding_model": params.get("embedding", {}).get("model_name", settings.embedding_model),
        "chunk_size": params.get("chunking", {}).get("chunk_size"),
        "retrieval_k": params.get("retrieval", {}).get("k"),
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    meta = request.metadata.model_dump() if request.metadata else None
    return rag.analyze(
        alert_text=request.alert_text,
        k=request.k,
        metadata=meta,
        auto_response=request.auto_response,
    )


@app.post("/analyze/stream")
def analyze_stream(request: AnalyzeRequest):
    meta = request.metadata.model_dump() if request.metadata else None

    def generate():
        for event in rag.stream_analyze(
            alert_text=request.alert_text,
            k=request.k,
            metadata=meta,
            auto_response=request.auto_response,
        ):
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")
    

