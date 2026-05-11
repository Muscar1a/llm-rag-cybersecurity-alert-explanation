from qdrant_client import QdrantClient, models
from qdrant_client.http.exceptions import ResponseHandlingException
from urllib.parse import urlparse
from .settings import settings

def build_client() -> QdrantClient:
    if settings.qdrant_url:
        return QdrantClient(
            url=settings.qdrant_url,
            api_key=settings.qdrant_api_key,
            timeout=settings.qdrant_timeout,
        )

    host = settings.qdrant_host.strip()
    if host.startswith("http://") or host.startswith("https://"):
        parsed = urlparse(host)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(
                "Invalid qdrant_host URL. Use a valid URL (e.g., http://localhost:6333) "
                "or set qdrant_host to only the hostname."
            )
        url = host if parsed.port else f"{parsed.scheme}://{parsed.hostname}:{settings.qdrant_port}"
        return QdrantClient(
            url=url,
            api_key=settings.qdrant_api_key,
            timeout=settings.qdrant_timeout,
        )

    return QdrantClient(
        host=host,
        port=settings.qdrant_port,
        https=settings.qdrant_https,
        api_key=settings.qdrant_api_key,
        timeout=settings.qdrant_timeout,
    )
    

def ensure_collection(client: QdrantClient, vector_size: int) -> None:
    try:
        existing = [c.name for c in client.get_collections().collections]
    except ResponseHandlingException as exc:
        message = str(exc)
        if "WRONG_VERSION_NUMBER" in message:
            raise RuntimeError(
                "Qdrant connection failed due to HTTP/HTTPS mismatch. "
                "If Qdrant runs locally on Docker (port 6333), use HTTP. "
                "Set qdrant_url=http://localhost:6333 or keep qdrant_host=localhost and qdrant_https=false."
            ) from exc
        raise

    if settings.qdrant_collection in existing:
        return 
    
    client.create_collection(
        collection_name=settings.qdrant_collection,
        vectors_config=models.VectorParams(
            size=vector_size,
            distance=models.Distance.COSINE
        )
    )
