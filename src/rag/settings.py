from pydantic_settings import BaseSettings, SettingsConfigDict
import os


class Settings(BaseSettings):
    qdrant_url: str | None = None
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_https: bool = False
    qdrant_api_key: str | None = None
    qdrant_collection: str = "cyber_chunks"
    qdrant_timeout: int = 69
    
    # embedding_model: str = "intfloat/e5-small-v2"
    embedding_model: str = "BAAI/bge-base-en-v1.5"
    
    ollama_host: str = "http://localhost:11434"
    ollama_model: str | None = None
    ollama_num_ctx: int = 5120

    deepseek_api_key: str | None = None
    deepseek_model: str = "deepseek-chat"
    
    # Hugging Face Token for API access
    hf_token: str | None = None
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
settings = Settings()

# Export HF_TOKEN to environment variables for Hugging Face libraries to access
if settings.hf_token:
    os.environ["HF_TOKEN"] = settings.hf_token

