from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def _dt_to_str(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _dt_from_str(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


@dataclass
class SecretVersion:
    version: str
    value: str
    content_type: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    not_before: datetime | None = None
    expires_on: datetime | None = None
    created_on: datetime = field(default_factory=utc_now)
    updated_on: datetime = field(default_factory=utc_now)
    deleted_on: datetime | None = None
    scheduled_purge_on: datetime | None = None
    recovery_id: str | None = None

    def clone(self) -> "SecretVersion":
        return SecretVersion(
            version=self.version,
            value=self.value,
            content_type=self.content_type,
            tags=dict(self.tags),
            enabled=self.enabled,
            not_before=self.not_before,
            expires_on=self.expires_on,
            created_on=self.created_on,
            updated_on=self.updated_on,
            deleted_on=self.deleted_on,
            scheduled_purge_on=self.scheduled_purge_on,
            recovery_id=self.recovery_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "value": self.value,
            "content_type": self.content_type,
            "tags": dict(self.tags),
            "enabled": self.enabled,
            "not_before": _dt_to_str(self.not_before),
            "expires_on": _dt_to_str(self.expires_on),
            "created_on": _dt_to_str(self.created_on),
            "updated_on": _dt_to_str(self.updated_on),
            "deleted_on": _dt_to_str(self.deleted_on),
            "scheduled_purge_on": _dt_to_str(self.scheduled_purge_on),
            "recovery_id": self.recovery_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecretVersion":
        return cls(
            version=payload["version"],
            value=payload["value"],
            content_type=payload.get("content_type"),
            tags=dict(payload.get("tags") or {}),
            enabled=payload.get("enabled", True),
            not_before=_dt_from_str(payload.get("not_before")),
            expires_on=_dt_from_str(payload.get("expires_on")),
            created_on=_dt_from_str(payload.get("created_on")) or utc_now(),
            updated_on=_dt_from_str(payload.get("updated_on")) or utc_now(),
            deleted_on=_dt_from_str(payload.get("deleted_on")),
            scheduled_purge_on=_dt_from_str(payload.get("scheduled_purge_on")),
            recovery_id=payload.get("recovery_id"),
        )


class SecretStore:
    def __init__(self, state_path: Path | None = None) -> None:
        self._state_path = state_path
        self._secrets: dict[str, list[SecretVersion]] = {}
        self._deleted: dict[str, SecretVersion] = {}
        self._load()

    def _load(self) -> None:
        if self._state_path is None or not self._state_path.exists():
            return
        payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        self._secrets = {
            name: [SecretVersion.from_dict(item) for item in versions]
            for name, versions in payload.get("secrets", {}).items()
        }
        self._deleted = {
            name: SecretVersion.from_dict(secret)
            for name, secret in payload.get("deleted", {}).items()
        }

    def _save(self) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "secrets": {
                name: [version.to_dict() for version in versions]
                for name, versions in self._secrets.items()
            },
            "deleted": {
                name: secret.to_dict()
                for name, secret in self._deleted.items()
            },
        }
        self._state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def set_secret(self, name: str, version: SecretVersion) -> SecretVersion:
        if name in self._deleted:
            self._deleted.pop(name, None)
        self._secrets.setdefault(name, []).append(version)
        self._save()
        return version

    def has_secret(self, name: str) -> bool:
        return name in self._secrets

    def list_properties(self) -> list[tuple[str, SecretVersion]]:
        items: list[tuple[str, SecretVersion]] = []
        for name, versions in self._secrets.items():
            latest = versions[-1]
            if latest.deleted_on is None:
                items.append((name, latest))
        return items

    def list_versions(self, name: str) -> list[SecretVersion]:
        return [version for version in self._secrets.get(name, []) if version.deleted_on is None]

    def get_secret(self, name: str, version: str | None = None, include_deleted: bool = False) -> SecretVersion | None:
        versions = self._secrets.get(name)
        if not versions:
            return None
        if version is None:
            candidate = versions[-1]
            if candidate.deleted_on and not include_deleted:
                return None
            return candidate
        for item in versions:
            if item.version == version:
                if item.deleted_on and not include_deleted:
                    return None
                return item
        return None

    def update_secret(
        self,
        name: str,
        version: str | None,
        *,
        content_type: str | None,
        tags: dict[str, str] | None,
        enabled: bool | None,
        not_before: datetime | None,
        expires_on: datetime | None,
    ) -> SecretVersion | None:
        secret = self.get_secret(name, version=version)
        if secret is None:
            return None

        if content_type is not None:
            secret.content_type = content_type
        if tags is not None:
            secret.tags = dict(tags)
        if enabled is not None:
            secret.enabled = enabled
        if not_before is not None:
            secret.not_before = not_before
        if expires_on is not None:
            secret.expires_on = expires_on
        secret.updated_on = utc_now()
        self._save()
        return secret

    def delete_secret(self, name: str) -> SecretVersion | None:
        versions = self._secrets.get(name)
        if not versions:
            return None

        deleted_at = utc_now()
        scheduled_purge = deleted_at
        for version in versions:
            version.deleted_on = deleted_at
            version.scheduled_purge_on = scheduled_purge

        latest = versions[-1].clone()
        latest.deleted_on = deleted_at
        latest.scheduled_purge_on = scheduled_purge
        self._deleted[name] = latest
        self._save()
        return latest

    def get_deleted_secret(self, name: str) -> SecretVersion | None:
        deleted = self._deleted.get(name)
        return deleted.clone() if deleted else None

    def list_deleted(self) -> list[tuple[str, SecretVersion]]:
        return [(name, secret.clone()) for name, secret in self._deleted.items()]

    def purge_deleted_secret(self, name: str) -> bool:
        deleted = self._deleted.pop(name, None)
        removed = self._secrets.pop(name, None)
        if deleted is not None or removed is not None:
            self._save()
        return deleted is not None or removed is not None

    def recover_deleted_secret(self, name: str) -> SecretVersion | None:
        versions = self._secrets.get(name)
        if not versions or name not in self._deleted:
            return None

        for version in versions:
            version.deleted_on = None
            version.scheduled_purge_on = None

        self._deleted.pop(name, None)
        latest = versions[-1]
        latest.updated_on = utc_now()
        self._save()
        return latest

    def backup_secret(self, name: str) -> bytes | None:
        versions = self._secrets.get(name)
        if not versions:
            return None

        payload = {
            "name": name,
            "versions": [version.to_dict() for version in versions],
            "deleted": self._deleted[name].to_dict() if name in self._deleted else None,
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return encoded.rstrip(b"=")

    def restore_secret(self, backup_blob: bytes | str) -> tuple[str, SecretVersion]:
        if isinstance(backup_blob, str):
            backup_blob = backup_blob.encode("ascii")

        padding = b"=" * (-len(backup_blob) % 4)
        payload = json.loads(base64.urlsafe_b64decode(backup_blob + padding).decode("utf-8"))
        name = payload["name"]
        if self.has_secret(name):
            raise ValueError(name)

        versions = [SecretVersion.from_dict(item) for item in payload["versions"]]
        self._secrets[name] = versions
        if payload.get("deleted"):
            self._deleted[name] = SecretVersion.from_dict(payload["deleted"])
        latest = versions[-1]
        self._save()
        return name, latest
