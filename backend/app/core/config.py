from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = (
        "postgresql://idsips:change-me-in-development@postgres:5432/idsips"
    )

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://redis:6379/0"

    # ── Kafka ─────────────────────────────────────────────────────────────────
    kafka_bootstrap_servers: str = "kafka:9092"
    kafka_alert_topic: str = "ids.alerts"
    kafka_blocked_topic: str = "ids.blocked"

    # ── OpenSearch ────────────────────────────────────────────────────────────
    opensearch_url: str = "http://opensearch:9200"
    opensearch_index: str = "ids-alerts"

    # ── JWT Auth ──────────────────────────────────────────────────────────────
    jwt_secret: str = "replace-with-a-long-random-secret"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 10080  # 7 days
    jwt_refresh_expire_days: int = 7

    # ── CORS ──────────────────────────────────────────────────────────────────
    cors_origins: str = "http://localhost:3000"

    # ── Admin seed ────────────────────────────────────────────────────────────
    admin_email: str = "admin@ids.local"
    admin_password: str = "AdminPassword1!"

    # ── App ───────────────────────────────────────────────────────────────────
    app_env: str = "development"
    log_level: str = "INFO"

    @property
    def db_url_psycopg(self) -> str:
        """Normalise the URL for psycopg (no +psycopg dialect prefix)."""
        return self.database_url.replace("postgresql+psycopg://", "postgresql://")

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
