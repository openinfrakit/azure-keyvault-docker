from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, status

from azure_keyvault_docker.config import Settings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


@dataclass
class TokenClaims:
    audience: str
    issuer: str
    subject: str
    tenant_id: str
    expires_at: datetime


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def issue_token(self, tenant_id: str, client_id: str, client_secret: str, scope: str) -> dict[str, str | int]:
        if not tenant_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_tenant")
        if not client_id or not client_secret:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_client")

        expires_at = datetime.now(UTC) + timedelta(hours=1)
        token = self._encode_token(
            TokenClaims(
                audience=scope,
                issuer=f"{self._settings.authority}/{tenant_id}",
                subject=client_id,
                tenant_id=tenant_id,
                expires_at=expires_at,
            )
        )
        return {
            "token_type": "Bearer",
            "expires_in": 3600,
            "ext_expires_in": 3600,
            "access_token": token,
        }

    def validate_token(self, authorization: str | None) -> TokenClaims:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_token")

        token = authorization[7:]
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            expected_signature = _b64url(
                hmac.new(
                    self._settings.token_signing_key.encode("utf-8"),
                    signing_input,
                    hashlib.sha256,
                ).digest()
            )
            if not hmac.compare_digest(signature_b64, expected_signature):
                raise ValueError("invalid signature")
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_token") from exc

        expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)
        if expires_at <= datetime.now(UTC):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="expired_token")

        return TokenClaims(
            audience=payload["aud"],
            issuer=payload["iss"],
            subject=payload["sub"],
            tenant_id=payload["tid"],
            expires_at=expires_at,
        )

    def _encode_token(self, claims: TokenClaims) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "aud": claims.audience,
            "iss": claims.issuer,
            "sub": claims.subject,
            "tid": claims.tenant_id,
            "nbf": int(datetime.now(UTC).timestamp()),
            "exp": int(claims.expires_at.timestamp()),
        }
        header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature_b64 = _b64url(
            hmac.new(
                self._settings.token_signing_key.encode("utf-8"),
                signing_input,
                hashlib.sha256,
            ).digest()
        )
        return f"{header_b64}.{payload_b64}.{signature_b64}"
