# azure-keyvault-docker

Local Azure Key Vault emulator focused on compatibility with the Python Azure SDK.

Current scope:
- Secrets operations only
- Local OAuth2 authority for `ClientSecretCredential`
- Local HTTPS endpoint because the Azure SDK requires TLS
- Disk-backed secret persistence across restarts
- Zero host setup when using the Azure SDK with `connection_verify=False`

Development:

```powershell
uv sync --dev
uv run pytest
uv run python -m azure_keyvault_docker
```

Python SDK usage:

```python
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

credential = ClientSecretCredential(
    tenant_id="...",
    client_id="...",
    client_secret="...",
    authority="127.0.0.1:8443",
    disable_instance_discovery=True,
    connection_verify=False,
)

client = SecretClient(
    vault_url="https://127.0.0.1:8443",
    credential=credential,
    verify_challenge_resource=False,
    connection_verify=False,
)
```

Notes:
- The emulator generates a local self-signed certificate in `.local-certs/`.
- For Docker-first usage, the intended path is to use the official Azure SDK with `connection_verify=False` so no local trust-store setup is required.
- Secret state is persisted in `.local-data/secrets.json`.
- The host and port can be overridden with `EMULATOR_HOST` and `EMULATOR_PORT`.
- This is intentionally shaped around the official Python clients first, then we can grow API fidelity from there.
