# azure-keyvault-docker

Local Azure Key Vault emulator focused on compatibility with the official Azure SDKs for secrets.

Current scope:
- Secrets operations only
- Local OAuth2 authority for `ClientSecretCredential`
- Local HTTPS endpoint because the Azure SDK requires TLS
- Disk-backed secret persistence across restarts
- Docker-first usage with no host certificate installation when using `connection_verify=False`
- Tested with both Python and Java secrets SDKs

## Quick Start

Run locally in development:

```powershell
uv sync --dev
uv run pytest
uv run python -m azure_keyvault_docker
```

Run with Docker:

```powershell
docker pull ashiqabdulkhader/azure-keyvault-docker:latest
docker run --rm -p 8443:8443 ashiqabdulkhader/azure-keyvault-docker:latest
```

Docker Hub image:
- `ashiqabdulkhader/azure-keyvault-docker`

## SDK Usage

### Python

Tested with:
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
    additionally_allowed_tenants=["*"],
    connection_verify=False,
)

client = SecretClient(
    vault_url="https://127.0.0.1:8443",
    credential=credential,
    verify_challenge_resource=False,
    connection_verify=False,
)
```

### Java

Tested with:
- `com.azure:azure-security-keyvault-secrets:4.8.0`
- `com.azure:azure-identity:1.11.0`

```java
import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

HttpClient httpClient = new NettyAsyncHttpClientBuilder(
    reactor.netty.http.client.HttpClient.create().secure(ssl -> ssl.sslContext(
        SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
    ))
).build();

TokenCredential credential = new ClientSecretCredentialBuilder()
    .tenantId("any-tenant-id-you-want-to-use")
    .clientId("any-client-id-you-want-to-use")
    .clientSecret("any-client-secret-you-want-to-use")
    .authorityHost("https://127.0.0.1:8443")
    .disableInstanceDiscovery()
    .additionallyAllowedTenants("*")
    .httpClient(httpClient)
    .build();

SecretClient client = new SecretClientBuilder()
    .vaultUrl("https://127.0.0.1:8443")
    .credential(credential)
    .httpClient(httpClient)
    .disableChallengeResourceVerification()
    .buildClient();
```

## Sample Architecture

```text
+------------------------+
| Application            |
| - Azure Identity SDK   |
| - Key Vault SDK        |
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

1. Your app creates a client credential pointing at the emulator authority.
2. The Key Vault SDK sends an unauthenticated request to the local vault URL.
3. The emulator responds with a Key Vault-style `WWW-Authenticate` challenge.
4. `azure-identity` discovers the emulator's OpenID configuration and requests a token from the local token endpoint.
5. The emulator accepts the caller-provided tenant, client ID, and client secret and issues a local token.
6. The SDK retries the original request with a bearer token.
7. The emulator serves the request from the local secrets store and persists changes to disk.

Important compatibility note:
- The emulator uses a `/common` challenge authority so both Python and Java SDKs can complete the Key Vault challenge flow locally.
- Because of that, the client credential examples include wildcard multitenant allowance: `additionally_allowed_tenants=["*"]` in Python and `.additionallyAllowedTenants("*")` in Java.

## Tests

The SDK integration tests are split by language:
- [tests/python/test_sdk_integration.py](tests/python/test_sdk_integration.py)
- [tests/java/test_java_sdk_integration.py](tests/java/test_java_sdk_integration.py)
- [tests/java/src/test/java/dev/ashiqabdulkhader/keyvaultdocker/KeyVaultJavaSdkIntegrationTest.java](tests/java/src/test/java/dev/ashiqabdulkhader/keyvaultdocker/KeyVaultJavaSdkIntegrationTest.java)

Run everything with:

```powershell
uv run pytest
```

The Java path bootstraps repo-local Maven automatically through [tests/java/run_maven.py](tests/java/run_maven.py), so no global Maven or Gradle install is required.

The implementation is split into:
- [src/azure_keyvault_docker/app.py](src/azure_keyvault_docker/app.py): HTTP routes, API-version checks, error shaping, and paging.
- [src/azure_keyvault_docker/auth.py](src/azure_keyvault_docker/auth.py): local token issuance and bearer validation.
- [src/azure_keyvault_docker/store.py](src/azure_keyvault_docker/store.py): in-memory plus disk-backed secret state.
- [src/azure_keyvault_docker/certs.py](src/azure_keyvault_docker/certs.py): local HTTPS certificate generation.
- [src/azure_keyvault_docker/config.py](src/azure_keyvault_docker/config.py): runtime configuration and ports.

## Compatibility

### SDK Compatibility

| Language | SDK | Version | Status | Notes |
| --- | --- | --- | --- | --- |
| Python | `azure-identity` | `1.19.x` via dev env | Supported | Tested with `ClientSecretCredential`. |
| Python | `azure-keyvault-secrets` | `4.9.x` via dev env | Supported | Full primary integration target today. |
| Java | `com.azure:azure-identity` | `1.11.0` | Supported | Tested with `ClientSecretCredentialBuilder`. |
| Java | `com.azure:azure-security-keyvault-secrets` | `4.8.0` | Supported | Tested against emulator with service version `7.5`. |
| Any | Keys SDKs | n/a | Not implemented | Keys API not started. |
| Any | Certificates SDKs | n/a | Not implemented | Certificates API not started. |

### Operation Compatibility

| Operation | Python SDK | Java SDK | Notes |
| --- | --- | --- | --- |
| Set secret | Supported | Supported | Creates a new version when the secret already exists. |
| Get secret | Supported | Supported | Latest and explicit version paths supported. |
| Update properties | Supported | Supported | Supports tags, content type, enabled, `nbf`, `exp`. |
| List secrets | Supported | Supported | Paged responses supported. |
| List versions | Supported | Supported | Paged responses supported. |
| Delete secret | Supported | Supported | Soft-delete style flow. |
| Get deleted secret | Supported | Supported | Supported after delete. |
| List deleted secrets | Supported | Supported | Paged responses supported. |
| Recover deleted secret | Supported | Supported | Recovers latest active secret set. |
| Purge deleted secret | Supported | Supported | Removes deleted secret permanently from local store. |
| Backup secret | Supported | Supported | Backup format is emulator-local, not Azure-native. |
| Restore secret | Supported | Supported | Restores all stored versions from emulator backup. |
| Secret expiry enforcement | Partial | Partial | Metadata is stored, but expiry/disabled checks are not fully enforced on every operation. |
| API versions | `7.5`, `7.6` | `7.5` tested | Other versions return unsupported-version errors. |

## Notes

- The emulator generates a local self-signed certificate in `.local-certs/`.
- For Docker-first usage, the intended path is to disable certificate verification in the SDK client path instead of installing the local cert into the host trust store.
- Secret state is persisted in `.local-data/secrets.json`.
- The host and port can be overridden with `EMULATOR_HOST` and `EMULATOR_PORT`.
- The emulator does not require `.env` or preconfigured client credentials. It accepts whatever non-empty tenant/client/secret the SDK caller provides.
- This project is intentionally shaped around real SDK behavior first, then broader Azure fidelity over time.
