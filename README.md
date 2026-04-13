# azure-keyvault-docker

Local Azure Key Vault emulator focused on compatibility with the Python Azure SDK.

Current scope:
- Secrets operations only
- Local OAuth2 authority for `ClientSecretCredential`
- Local HTTPS endpoint because the Azure SDK requires TLS
- Disk-backed secret persistence across restarts
- Docker-first usage with no host certificate installation when using `connection_verify=False`

## Quick Start

Run locally in development:

```powershell
uv sync --dev
uv run pytest
uv run python -m azure_keyvault_docker
```

Run with Docker:

```powershell
docker build -t azure-keyvault-docker .
docker run --rm -p 8443:8443 azure-keyvault-docker
```

## Python SDK Usage

This emulator is designed around the official Python SDK path:
- `azure-identity` for token acquisition
- `azure-keyvault-secrets` for secrets operations
- no pre-registered client credentials are required

```python
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient

credential = ClientSecretCredential(
    tenant_id="any-tenant-id-you-want-to-use",
    client_id="any-client-id-you-want-to-use",
    client_secret="any-client-secret-you-want-to-use",
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

## Sample Architecture

```text
+------------------------+
| Python application     |
| - azure-identity       |
| - azure-keyvault-*     |
+-----------+------------+
            |
            | HTTPS requests
            | bearer challenge flow
            v
+------------------------+
| azure-keyvault-docker  |
| FastAPI service        |
|                        |
| 1. OIDC discovery      |
| 2. token endpoint      |
| 3. Key Vault secrets   |
|    REST endpoints      |
+-----------+------------+
            |
            | read/write
            v
+------------------------+
| Local persistence      |
| .local-data/secrets    |
| .json                  |
+------------------------+
```

## How It Works

1. Your Python app creates a `ClientSecretCredential` pointing at the emulator authority.
2. The Key Vault SDK sends an unauthenticated request to the local vault URL.
3. The emulator responds with a Key Vault-style `WWW-Authenticate` challenge.
4. `azure-identity` discovers the emulator's OpenID configuration and requests a token from the local token endpoint.
5. The emulator accepts the caller-provided tenant, client ID, and client secret and issues a local token.
6. The SDK retries the original request with a bearer token.
7. The emulator serves the request from the local secrets store and persists changes to disk.

The implementation is split into:
- [src/azure_keyvault_docker/app.py](/C:/Users/MUKHADE/Workspace/azure-keyvault-docker/src/azure_keyvault_docker/app.py): HTTP routes, API-version checks, error shaping, and paging.
- [src/azure_keyvault_docker/auth.py](/C:/Users/MUKHADE/Workspace/azure-keyvault-docker/src/azure_keyvault_docker/auth.py): local token issuance and bearer validation.
- [src/azure_keyvault_docker/store.py](/C:/Users/MUKHADE/Workspace/azure-keyvault-docker/src/azure_keyvault_docker/store.py): in-memory plus disk-backed secret state.
- [src/azure_keyvault_docker/certs.py](/C:/Users/MUKHADE/Workspace/azure-keyvault-docker/src/azure_keyvault_docker/certs.py): local HTTPS certificate generation.
- [src/azure_keyvault_docker/config.py](/C:/Users/MUKHADE/Workspace/azure-keyvault-docker/src/azure_keyvault_docker/config.py): runtime configuration and ports.

## Compatibility

### SDK Compatibility

| SDK | Status | Notes |
| --- | --- | --- |
| `azure-identity` | Supported | Tested with `ClientSecretCredential` against local authority. |
| `azure-keyvault-secrets` | Supported | Primary compatibility target. |
| `azure-keyvault-keys` | Not implemented | Keys API not started. |
| `azure-keyvault-certificates` | Not implemented | Certificates API not started. |

### Operation Compatibility

| Operation | SDK method | Status | Notes |
| --- | --- | --- | --- |
| Set secret | `set_secret` | Supported | Creates a new version when the secret already exists. |
| Get secret | `get_secret` | Supported | Latest and explicit version paths supported. |
| Update properties | `update_secret_properties` | Supported | Supports tags, content type, enabled, `nbf`, `exp`. |
| List secrets | `list_properties_of_secrets` | Supported | Paged responses supported. |
| List versions | `list_properties_of_secret_versions` | Supported | Paged responses supported. |
| Delete secret | `begin_delete_secret` | Supported | Soft-delete style flow. |
| Get deleted secret | `get_deleted_secret` | Supported | Supported after delete. |
| List deleted secrets | `list_deleted_secrets` | Supported | Paged responses supported. |
| Recover deleted secret | `begin_recover_deleted_secret` | Supported | Recovers latest active secret set. |
| Purge deleted secret | `purge_deleted_secret` | Supported | Removes deleted secret permanently from local store. |
| Backup secret | `backup_secret` | Supported | Backup format is emulator-local, not Azure-native. |
| Restore secret | `restore_secret_backup` | Supported | Restores all stored versions from emulator backup. |
| Secret expiry enforcement | Read-time enforcement | Partial | Metadata is stored, but expiry/disabled checks are not fully enforced on every operation. |
| API versions | `api-version=7.6` | Supported | Other versions currently return unsupported-version errors. |

## Notes

- The emulator generates a local self-signed certificate in `.local-certs/`.
- For Docker-first usage, the intended path is to use the official Azure SDK with `connection_verify=False` so no local trust-store setup is required.
- Secret state is persisted in `.local-data/secrets.json`.
- The host and port can be overridden with `EMULATOR_HOST` and `EMULATOR_PORT`.
- The emulator does not require `.env` or preconfigured client credentials. It accepts whatever non-empty tenant/client/secret the SDK caller provides.
- This project is intentionally shaped around real SDK behavior first, then broader Azure fidelity over time.
