from pydantic_settings import BaseSettings, SettingsConfigDict
import os


class Settings(BaseSettings):
    qdrant_url: str | None = None
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_https: bool = False
    qdrant_api_key: str | None = None
    qdrant_collection: str = "cyber_chunks"
    qdrant_timeout: int = 60

    embedding_model: str = "BAAI/bge-base-en-v1.5"
    
    vllm_base_url: str = "http://localhost:8001/v1"
    vllm_model: str | None = None
    vllm_max_tokens: int = 4096

    openai_api_key: str | None = None
    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-v4-flash"
    gemini_api_key: str | None = None
    glm_api_key: str | None = None
    kimi_api_key: str | None = None
    grok_api_key: str | None = None
    
    # Hugging Face Token for API access
    hf_token: str | None = None

    # Auto-response
    auto_response_enabled: bool = False
    auto_response_mode: str = "dry_run"
    auto_response_severity_threshold: str = "Critical"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
settings = Settings()

# Export HF_TOKEN to environment variables for Hugging Face libraries to access
if settings.hf_token:
    os.environ["HF_TOKEN"] = settings.hf_token

