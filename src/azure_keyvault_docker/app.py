from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from azure_keyvault_docker.auth import Authenticator
from azure_keyvault_docker.config import Settings, get_settings
from azure_keyvault_docker.store import SecretStore, SecretVersion


app = FastAPI(title="Azure Key Vault Docker Emulator", version="0.1.0")
store: SecretStore | None = None


def get_authenticator(settings: Annotated[Settings, Depends(get_settings)]) -> Authenticator:
    return Authenticator(settings)


def get_store() -> SecretStore:
    global store
    if store is None:
        store = SecretStore(get_settings().state_path)
    return store


@app.on_event("startup")
def startup_event() -> None:
    get_store()


def _secret_id(request: Request, name: str, version: str) -> str:
    return str(request.base_url).rstrip("/") + f"/secrets/{name}/{version}"


def _deleted_secret_id(request: Request, name: str) -> str:
    return str(request.base_url).rstrip("/") + f"/deletedsecrets/{name}"


def _unix_timestamp(value: datetime | None) -> int | None:
    return int(value.timestamp()) if value else None


def _error_payload(code: str, message: str) -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message}}


def _error_response(status_code: int, code: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=_error_payload(code, message), headers=headers)


def _raise_kv_error(status_code: int, code: str, message: str) -> None:
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _challenge_headers(settings: Settings) -> dict[str, str]:
    return {
        "WWW-Authenticate": (
            f'Bearer authorization="{settings.authority}/{settings.kv_tenant_id}", '
            'resource="https://vault.azure.net"'
        )
    }


def _validate_api_version(settings: Settings, api_version: str | None) -> str:
    if api_version is None:
        _raise_kv_error(
            status.HTTP_400_BAD_REQUEST,
            "MissingApiVersionParameter",
            "The api-version query parameter is required.",
        )
    if api_version not in settings.supported_api_versions:
        _raise_kv_error(
            status.HTTP_400_BAD_REQUEST,
            "UnsupportedApiVersion",
            f"The HTTP resource that matches the request URI does not support the API version '{api_version}'.",
        )
    return api_version


def _secret_attributes(secret: SecretVersion) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "enabled": secret.enabled,
        "created": _unix_timestamp(secret.created_on),
        "updated": _unix_timestamp(secret.updated_on),
        "recoveryLevel": "Recoverable+Purgeable",
    }
    if secret.not_before is not None:
        attributes["nbf"] = _unix_timestamp(secret.not_before)
    if secret.expires_on is not None:
        attributes["exp"] = _unix_timestamp(secret.expires_on)
    return attributes


def _secret_bundle(request: Request, name: str, secret: SecretVersion, include_value: bool) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": _secret_id(request, name, secret.version),
        "attributes": _secret_attributes(secret),
    }
    if include_value:
        payload["value"] = secret.value
    if secret.content_type is not None:
        payload["contentType"] = secret.content_type
    if secret.tags:
        payload["tags"] = dict(secret.tags)
    return payload


def _deleted_secret_bundle(request: Request, name: str, secret: SecretVersion, include_value: bool) -> dict[str, object]:
    payload = _secret_bundle(request, name, secret, include_value=include_value)
    payload["recoveryId"] = _deleted_secret_id(request, name)
    payload["deletedDate"] = _unix_timestamp(secret.deleted_on)
    payload["scheduledPurgeDate"] = _unix_timestamp(secret.scheduled_purge_on)
    return payload


def _items_page(items: list[dict[str, object]]) -> dict[str, object]:
    return {"value": items, "nextLink": None}


def _paged_items(
    request: Request,
    items: list[dict[str, object]],
    *,
    maxresults: int | None,
    skiptoken: str | None,
) -> dict[str, object]:
    if maxresults is None:
        return _items_page(items)
    if maxresults <= 0:
        _raise_kv_error(
            status.HTTP_400_BAD_REQUEST,
            "BadParameter",
            "The value of maxresults must be greater than 0.",
        )

    try:
        start = int(skiptoken or "0")
    except ValueError as exc:
        _raise_kv_error(status.HTTP_400_BAD_REQUEST, "BadParameter", "The skiptoken value is invalid.")
        raise AssertionError from exc

    end = start + maxresults
    page = items[start:end]
    next_link = None
    if end < len(items):
        next_link = str(request.url.include_query_params(skiptoken=str(end), maxresults=maxresults))
    return {"value": page, "nextLink": next_link}


def _parse_datetime(value: int | None) -> datetime | None:
    return datetime.fromtimestamp(value, tz=UTC) if value is not None else None


def _normalize_set_body(body: dict[str, Any]) -> dict[str, Any]:
    attributes = body.get("attributes") or {}
    if "value" not in body:
        _raise_kv_error(status.HTTP_400_BAD_REQUEST, "BadParameter", "The request body must include a secret value.")
    return {
        "value": body["value"],
        "content_type": body.get("contentType"),
        "tags": dict(body.get("tags") or {}),
        "enabled": attributes.get("enabled", True),
        "not_before": _parse_datetime(attributes.get("nbf")),
        "expires_on": _parse_datetime(attributes.get("exp")),
    }


def _normalize_update_body(body: dict[str, Any]) -> dict[str, Any]:
    attributes = body.get("attributes") or {}
    return {
        "content_type": body.get("contentType"),
        "tags": dict(body["tags"]) if "tags" in body else None,
        "enabled": attributes.get("enabled") if "enabled" in attributes else None,
        "not_before": _parse_datetime(attributes["nbf"]) if "nbf" in attributes else None,
        "expires_on": _parse_datetime(attributes["exp"]) if "exp" in attributes else None,
    }


def _backup_result(blob: bytes) -> dict[str, str]:
    return {"value": blob.decode("ascii")}


@app.middleware("http")
async def require_bearer_token(request: Request, call_next):
    if request.url.path == "/" or request.url.path.endswith("/oauth2/v2.0/token"):
        return await call_next(request)

    if request.url.path.endswith("/.well-known/openid-configuration"):
        return await call_next(request)

    if request.url.path.startswith("/secrets") or request.url.path.startswith("/deletedsecrets"):
        settings = get_settings()
        authorization = request.headers.get("Authorization")
        try:
            Authenticator(settings).validate_token(authorization)
        except HTTPException:
            return _error_response(
                status.HTTP_401_UNAUTHORIZED,
                "Unauthorized",
                "Request is missing a bearer or pop token.",
                headers=_challenge_headers(settings),
            )

    return await call_next(request)


@app.get("/")
def index(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, str]:
    return {
        "service": "azure-keyvault-docker",
        "vault_url": settings.vault_url,
        "authority": settings.authority,
        "ca_cert_path": str(settings.ca_cert_path),
        "state_path": str(settings.state_path),
    }


@app.post("/{tenant_id}/oauth2/v2.0/token")
def issue_token(
    tenant_id: str,
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    grant_type: Annotated[str, Form()],
    authenticator: Annotated[Authenticator, Depends(get_authenticator)],
) -> dict[str, str | int]:
    if grant_type != "client_credentials":
        _raise_kv_error(status.HTTP_400_BAD_REQUEST, "unsupported_grant_type", "Only client_credentials is supported.")
    return authenticator.issue_token(tenant_id, client_id, client_secret, scope)


@app.get("/{tenant_id}/v2.0/.well-known/openid-configuration")
def openid_configuration(
    tenant_id: str,
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str | list[str]]:
    issuer = f"{settings.authority}/{tenant_id}/v2.0"
    return {
        "issuer": issuer,
        "token_endpoint": f"{settings.authority}/{tenant_id}/oauth2/v2.0/token",
        "authorization_endpoint": f"{settings.authority}/{tenant_id}/oauth2/v2.0/authorize",
        "jwks_uri": f"{settings.authority}/{tenant_id}/discovery/v2.0/keys",
        "response_types_supported": ["token"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.put("/secrets/{name}")
def set_secret(
    name: str,
    request: Request,
    body: Annotated[dict[str, Any], Body(...)],
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    payload = _normalize_set_body(body)
    version = SecretVersion(
        version=secrets.token_hex(16),
        value=payload["value"],
        content_type=payload["content_type"],
        tags=payload["tags"],
        enabled=payload["enabled"],
        not_before=payload["not_before"],
        expires_on=payload["expires_on"],
    )
    get_store().set_secret(name, version)
    return _secret_bundle(request, name, version, include_value=True)


@app.patch("/secrets/{name}/{version}")
@app.patch("/secrets/{name}/")
def update_secret(
    name: str,
    request: Request,
    body: Annotated[dict[str, Any], Body(...)],
    version: str = "",
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    payload = _normalize_update_body(body)
    updated = get_store().update_secret(
        name,
        version or None,
        content_type=payload["content_type"],
        tags=payload["tags"],
        enabled=payload["enabled"],
        not_before=payload["not_before"],
        expires_on=payload["expires_on"],
    )
    if updated is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    return _secret_bundle(request, name, updated, include_value=False)


@app.get("/secrets/{name}")
@app.get("/secrets/{name}/")
def get_secret(
    name: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    secret = get_store().get_secret(name)
    if secret is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    return _secret_bundle(request, name, secret, include_value=True)


@app.get("/secrets")
def list_secrets(
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
    maxresults: int | None = None,
    skiptoken: str | None = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    items = [_secret_bundle(request, name, secret, include_value=False) for name, secret in get_store().list_properties()]
    return _paged_items(request, items, maxresults=maxresults, skiptoken=skiptoken)


@app.get("/secrets/{name}/versions")
def list_secret_versions(
    name: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
    maxresults: int | None = None,
    skiptoken: str | None = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    if get_store().get_secret(name, include_deleted=True) is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    items = [_secret_bundle(request, name, version, include_value=False) for version in get_store().list_versions(name)]
    return _paged_items(request, items, maxresults=maxresults, skiptoken=skiptoken)


@app.get("/secrets/{name}/{version}")
def get_secret_version(
    name: str,
    version: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    secret = get_store().get_secret(name, version=version)
    if secret is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    return _secret_bundle(request, name, secret, include_value=True)


@app.post("/secrets/{name}/backup")
def backup_secret(
    name: str,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, str]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    backup_blob = get_store().backup_secret(name)
    if backup_blob is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    return _backup_result(backup_blob)


@app.post("/secrets/restore")
def restore_secret(
    request: Request,
    body: Annotated[dict[str, Any], Body(...)],
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    if "value" not in body:
        _raise_kv_error(status.HTTP_400_BAD_REQUEST, "BadParameter", "The request body must include a backup value.")
    try:
        name, restored = get_store().restore_secret(body["value"])
    except ValueError as exc:
        _raise_kv_error(
            status.HTTP_409_CONFLICT,
            "SecretAlreadyExists",
            f"A secret with name '{exc.args[0]}' already exists.",
        )
    except Exception as exc:
        _raise_kv_error(status.HTTP_400_BAD_REQUEST, "BadParameter", f"The backup blob is invalid: {exc}")
    return _secret_bundle(request, name, restored, include_value=False)


@app.delete("/secrets/{name}")
def delete_secret(
    name: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    secret = get_store().delete_secret(name)
    if secret is None:
        _raise_kv_error(status.HTTP_404_NOT_FOUND, "SecretNotFound", f"A secret with name '{name}' was not found.")
    return _deleted_secret_bundle(request, name, secret, include_value=True)


@app.get("/deletedsecrets")
def list_deleted_secrets(
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
    maxresults: int | None = None,
    skiptoken: str | None = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    items = [
        _deleted_secret_bundle(request, name, secret, include_value=False)
        for name, secret in get_store().list_deleted()
    ]
    return _paged_items(request, items, maxresults=maxresults, skiptoken=skiptoken)


@app.get("/deletedsecrets/{name}")
def get_deleted_secret(
    name: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    secret = get_store().get_deleted_secret(name)
    if secret is None:
        _raise_kv_error(
            status.HTTP_404_NOT_FOUND,
            "SecretNotFound",
            f"A deleted secret with name '{name}' was not found.",
        )
    return _deleted_secret_bundle(request, name, secret, include_value=True)


@app.post("/deletedsecrets/{name}/recover")
def recover_deleted_secret(
    name: str,
    request: Request,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> dict[str, object]:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    secret = get_store().recover_deleted_secret(name)
    if secret is None:
        _raise_kv_error(
            status.HTTP_404_NOT_FOUND,
            "SecretNotFound",
            f"A deleted secret with name '{name}' was not found.",
        )
    return _secret_bundle(request, name, secret, include_value=True)


@app.delete("/deletedsecrets/{name}", status_code=status.HTTP_204_NO_CONTENT)
def purge_deleted_secret(
    name: str,
    api_version: Annotated[str | None, Query(alias="api-version")] = None,
) -> Response:
    settings = get_settings()
    _validate_api_version(settings, api_version)
    purged = get_store().purge_deleted_secret(name)
    if not purged:
        _raise_kv_error(
            status.HTTP_404_NOT_FOUND,
            "SecretNotFound",
            f"A deleted secret with name '{name}' was not found.",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.exception_handler(HTTPException)
def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, dict) else {"code": str(exc.detail), "message": str(exc.detail)}
    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        settings = get_settings()
        return JSONResponse(status_code=exc.status_code, content={"error": detail}, headers=_challenge_headers(settings))
    return JSONResponse(status_code=exc.status_code, content={"error": detail})
