from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


load_dotenv(Path(".env"))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    host: str = Field(default="127.0.0.1", validation_alias=AliasChoices("EMULATOR_HOST", "host"))
    port: int = Field(default=8443, validation_alias=AliasChoices("EMULATOR_PORT", "port"))
    issuer_host: str | None = Field(default=None, validation_alias=AliasChoices("EMULATOR_ISSUER_HOST", "issuer_host"))
    issuer_port: int | None = Field(default=None, validation_alias=AliasChoices("EMULATOR_ISSUER_PORT", "issuer_port"))
    vault_name: str = "local-vault"
    cert_dir: str = ".local-certs"
    data_dir: str = ".local-data"
    supported_api_versions: tuple[str, ...] = ("7.6",)

    kv_client_id: str = Field(alias="KV_CLIENT_ID")
    kv_client_secret: str = Field(alias="KV_CLIENT_SECRET")
    kv_tenant_id: str = Field(alias="KV_TENANT_ID")

    @property
    def authority(self) -> str:
        issuer_host = self.issuer_host or self.host
        issuer_port = self.issuer_port or self.port
        return f"https://{issuer_host}:{issuer_port}"

    @property
    def vault_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    @property
    def cert_path(self) -> Path:
        return Path(self.cert_dir) / "localhost.pem"

    @property
    def key_path(self) -> Path:
        return Path(self.cert_dir) / "localhost-key.pem"

    @property
    def ca_cert_path(self) -> Path:
        return Path(self.cert_dir) / "ca.pem"

    @property
    def ca_key_path(self) -> Path:
        return Path(self.cert_dir) / "ca-key.pem"

    @property
    def state_path(self) -> Path:
        return Path(self.data_dir) / "secrets.json"


@lru_cache
def get_settings() -> Settings:
    return Settings()
