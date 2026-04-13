from __future__ import annotations

import httpx
import pytest
from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError

from conftest import (
    STATE_FILE,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_TENANT_ID,
    launch_emulator,
    make_python_client,
    stop_process,
    wait_for_server,
)


def test_secret_crud_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    created = client.set_secret("example-secret", "hello")
    fetched = client.get_secret("example-secret")
    names = [item.name for item in client.list_properties_of_secrets()]
    deleted = client.begin_delete_secret("example-secret").result()

    assert created.value == "hello"
    assert fetched.value == "hello"
    assert "example-secret" in names
    assert deleted.name == "example-secret"


def test_secret_versions_and_properties_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    first = client.set_secret("versioned-secret", "v1", tags={"stage": "one"}, content_type="text/plain")
    second = client.set_secret("versioned-secret", "v2")
    props = client.update_secret_properties(
        "versioned-secret",
        second.properties.version,
        tags={"stage": "two"},
        content_type="application/custom",
        enabled=False,
    )
    versions = list(client.list_properties_of_secret_versions("versioned-secret"))
    fetched_first = client.get_secret("versioned-secret", first.properties.version)
    fetched_second = client.get_secret("versioned-secret")

    assert first.value == "v1"
    assert fetched_first.value == "v1"
    assert fetched_second.value == "v2"
    assert props.version == second.properties.version
    assert props.tags == {"stage": "two"}
    assert props.content_type == "application/custom"
    assert props.enabled is False
    assert {item.version for item in versions} == {first.properties.version, second.properties.version}


def test_deleted_secret_recover_and_purge_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    client.set_secret("recoverable-secret", "recover-me", tags={"kind": "demo"})
    deleted = client.begin_delete_secret("recoverable-secret").result()
    deleted_list = list(client.list_deleted_secrets())
    recovered = client.begin_recover_deleted_secret("recoverable-secret").result()
    client.begin_delete_secret("recoverable-secret").result()
    client.purge_deleted_secret("recoverable-secret")

    assert deleted.name == "recoverable-secret"
    assert any(item.name == "recoverable-secret" for item in deleted_list)
    assert recovered.name == "recoverable-secret"

    with pytest.raises(ResourceNotFoundError):
        client.get_deleted_secret("recoverable-secret")


def test_backup_and_restore_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    original = client.set_secret("backup-secret", "alpha", tags={"source": "test"}, content_type="text/plain")
    client.set_secret("backup-secret", "beta")
    backup = client.backup_secret("backup-secret")
    client.begin_delete_secret("backup-secret").result()
    client.purge_deleted_secret("backup-secret")

    restored = client.restore_secret_backup(backup)
    fetched = client.get_secret("backup-secret")
    versions = list(client.list_properties_of_secret_versions("backup-secret"))

    assert isinstance(backup, bytes)
    assert original.value == "alpha"
    assert restored.name == "backup-secret"
    assert fetched.value == "beta"
    assert fetched.properties.version == restored.version
    assert len(versions) == 2


def test_restore_conflicts_when_secret_exists(emulator):
    client = make_python_client(emulator["port"])

    client.set_secret("restore-conflict-secret", "first")
    backup = client.backup_secret("restore-conflict-secret")

    with pytest.raises(ResourceExistsError):
        client.restore_secret_backup(backup)


def test_paged_secret_listings_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    secret_names = [f"paged-secret-{index}" for index in range(5)]
    for index, name in enumerate(secret_names):
        client.set_secret(name, f"value-{index}")

    listed_names = [item.name for item in client.list_properties_of_secrets(max_page_size=2)]

    for name in secret_names:
        assert name in listed_names


def test_paged_version_and_deleted_listings_via_python_sdk(emulator):
    client = make_python_client(emulator["port"])

    client.set_secret("paged-versions-secret", "v1")
    client.set_secret("paged-versions-secret", "v2")
    client.set_secret("paged-versions-secret", "v3")
    version_ids = [item.version for item in client.list_properties_of_secret_versions("paged-versions-secret", max_page_size=1)]

    deleted_names = []
    for index in range(3):
        name = f"paged-deleted-secret-{index}"
        client.set_secret(name, f"value-{index}")
        client.begin_delete_secret(name).result()
        deleted_names.append(name)

    listed_deleted_names = [item.name for item in client.list_deleted_secrets(max_page_size=1)]

    assert len(version_ids) == 3
    for name in deleted_names:
        assert name in listed_deleted_names


def test_secrets_persist_to_disk_across_restart(emulator):
    client = make_python_client(emulator["port"])
    created = client.set_secret("persistent-secret", "survives-restart")
    assert STATE_FILE.exists()

    stop_process(emulator["process"])
    emulator["process"] = launch_emulator(emulator["env"])
    wait_for_server(emulator["port"])

    restarted_client = make_python_client(emulator["port"])
    fetched = restarted_client.get_secret("persistent-secret")

    assert fetched.value == "survives-restart"
    assert fetched.properties.version == created.properties.version


def test_unsupported_api_version_returns_azure_style_error(emulator):
    token_response = httpx.post(
        f"https://127.0.0.1:{emulator['port']}/{TEST_TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "scope": "https://vault.azure.net/.default",
        },
        verify=False,
    )
    token = token_response.json()["access_token"]
    response = httpx.get(
        f"https://127.0.0.1:{emulator['port']}/secrets/missing-secret",
        params={"api-version": "2099-01-01"},
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["error"]["code"] == "UnsupportedApiVersion"


def test_supported_api_versions_include_python_legacy_version(emulator):
    token_response = httpx.post(
        f"https://127.0.0.1:{emulator['port']}/{TEST_TENANT_ID}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": TEST_CLIENT_ID,
            "client_secret": TEST_CLIENT_SECRET,
            "scope": "https://vault.azure.net/.default",
        },
        verify=False,
    )
    token = token_response.json()["access_token"]
    response = httpx.get(
        f"https://127.0.0.1:{emulator['port']}/secrets/missing-secret",
        params={"api-version": "7.5"},
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SecretNotFound"
