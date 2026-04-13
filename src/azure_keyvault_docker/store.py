from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


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


class SecretStore:
    def __init__(self) -> None:
        self._secrets: dict[str, list[SecretVersion]] = {}
        self._deleted: dict[str, SecretVersion] = {}

    def set_secret(self, name: str, version: SecretVersion) -> SecretVersion:
        if name in self._deleted:
            self._deleted.pop(name, None)
        self._secrets.setdefault(name, []).append(version)
        return version

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
        return latest

    def get_deleted_secret(self, name: str) -> SecretVersion | None:
        deleted = self._deleted.get(name)
        return deleted.clone() if deleted else None

    def list_deleted(self) -> list[tuple[str, SecretVersion]]:
        return [(name, secret.clone()) for name, secret in self._deleted.items()]

    def purge_deleted_secret(self, name: str) -> bool:
        deleted = self._deleted.pop(name, None)
        removed = self._secrets.pop(name, None)
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
        return latest
