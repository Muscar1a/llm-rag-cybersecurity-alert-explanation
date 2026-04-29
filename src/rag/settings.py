from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    qdrant_url: str | None = None
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333
    qdrant_https: bool = False
    qdrant_api_key: str | None = None
    qdrant_collection: str = "cyber_chunks"
    qdrant_timeout: int = 69
    
    embedding_model: str = "intfloat/e5-small-v2"
    
    ollama_host: str = "http://localhost:11434"
    ollama_model: str | None = None
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
settings = Settings()
