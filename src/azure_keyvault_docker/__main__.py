import uvicorn

from azure_keyvault_docker.app import app
from azure_keyvault_docker.certs import ensure_localhost_certificate
from azure_keyvault_docker.config import get_settings


def main() -> None:
    settings = get_settings()
    ensure_localhost_certificate(settings)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        ssl_certfile=str(settings.cert_path),
        ssl_keyfile=str(settings.key_path),
    )


if __name__ == "__main__":
    main()
