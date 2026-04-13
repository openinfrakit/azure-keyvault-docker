from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


load_dotenv(Path(".env"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8443
    issuer_host: str = "127.0.0.1"
    issuer_port: int = 8443
    vault_name: str = "local-vault"
    cert_dir: str = ".local-certs"

    kv_client_id: str = Field(alias="KV_CLIENT_ID")
    kv_client_secret: str = Field(alias="KV_CLIENT_SECRET")
    kv_tenant_id: str = Field(alias="KV_TENANT_ID")

    @property
    def authority(self) -> str:
        return f"https://{self.issuer_host}:{self.issuer_port}"

    @property
    def vault_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    @property
    def cert_path(self) -> Path:
        return Path(self.cert_dir) / "localhost.pem"

    @property
    def key_path(self) -> Path:
        return Path(self.cert_dir) / "localhost-key.pem"


@lru_cache
def get_settings() -> Settings:
    return Settings()
