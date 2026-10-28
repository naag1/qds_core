from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="QDS_", extra="ignore")
    database_url: str = "sqlite:///./data/qds.db"
    redis_url: str = "redis://redis:6379/0"
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    sensor_token: str = ""
    jwt_secret: str = "change-me-before-production"
    jwt_expire_minutes: int = 30
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "change-me-before-production"
    model_manifest_path: str = "app/module2_detector/model_manifest.json"
    max_upload_bytes: int = 4 * 1024 * 1024 * 1024
    max_queue_depth: int = 1000
    flow_retention_days: int = 30
    environment: str = "development"
    allowed_origins: str = "http://localhost:8080"


@lru_cache
def get_settings() -> Settings:
    return Settings()
