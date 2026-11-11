from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str
    migration_database_url: str = ""
    redis_url: str
    keycloak_url: str
    # URL used by the backend to fetch JWKS when it differs from the public issuer URL
    # (e.g. inside docker-compose: issuer http://localhost:8080, JWKS via http://keycloak:8080).
    keycloak_internal_url: str = ""
    keycloak_realm: str
    keycloak_client_id: str

    # Fernet key that encrypts the API keys users store in the platform (see app/core/vault.py).
    # Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secrets_encryption_key: str = ""

    nvd_api_key: str = ""
    abuseipdb_key: str = ""
    vt_key: str = ""
    greynoise_key: str = ""
    hibp_key: str = ""
    geo_ip_url: str = "http://ip-api.com/json"

    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""

    cors_origins: str = "http://localhost:5173"
    log_level: str = "INFO"
    ioc_collector_enabled: bool = False
    leak_collector_enabled: bool = False
    ransomware_live_enabled: bool = False
    openphish_enabled: bool = False
    abuseipdb_collector_enabled: bool = False
    greynoise_enrichment_enabled: bool = False
    epss_collector_enabled: bool = True  # public API, no key required


@lru_cache()
def get_settings() -> Settings:
    return Settings()
