from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def wait_for_server() -> None:
    import httpx

    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            response = httpx.get("https://127.0.0.1:8443/", verify=False)
            if response.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("server did not start")


@pytest.fixture(scope="session")
def emulator():
    env = os.environ.copy()
    env.update({
        key: value
        for key, value in {
            "KV_CLIENT_ID": os.environ.get("KV_CLIENT_ID"),
            "KV_CLIENT_SECRET": os.environ.get("KV_CLIENT_SECRET"),
            "KV_TENANT_ID": os.environ.get("KV_TENANT_ID"),
        }.items()
        if value
    })
    cert_file = ROOT / ".local-certs" / "localhost.pem"
    env["REQUESTS_CA_BUNDLE"] = str(cert_file)
    env["SSL_CERT_FILE"] = str(cert_file)
    os.environ["REQUESTS_CA_BUNDLE"] = str(cert_file)
    os.environ["SSL_CERT_FILE"] = str(cert_file)
    process = subprocess.Popen(
        [sys.executable, "-m", "azure_keyvault_docker"],
        cwd=ROOT,
        env=env,
    )
    try:
        wait_for_server()
        yield process
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_secret_crud_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

    created = client.set_secret("example-secret", "hello")
    fetched = client.get_secret("example-secret")
    names = [item.name for item in client.list_properties_of_secrets()]
    deleted = client.begin_delete_secret("example-secret").result()

    assert created.value == "hello"
    assert fetched.value == "hello"
    assert "example-secret" in names
    assert deleted.name == "example-secret"


def test_secret_versions_and_properties_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

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


def test_deleted_secret_recover_and_purge_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

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


def test_backup_and_restore_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

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
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

    client.set_secret("restore-conflict-secret", "first")
    backup = client.backup_secret("restore-conflict-secret")

    with pytest.raises(ResourceExistsError):
        client.restore_secret_backup(backup)


def test_paged_secret_listings_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

    secret_names = [f"paged-secret-{index}" for index in range(5)]
    for index, name in enumerate(secret_names):
        client.set_secret(name, f"value-{index}")

    listed_names = [item.name for item in client.list_properties_of_secrets(max_page_size=2)]

    for name in secret_names:
        assert name in listed_names


def test_paged_version_and_deleted_listings_via_azure_sdk(emulator):
    _ = emulator
    credential = ClientSecretCredential(
        tenant_id=os.environ["KV_TENANT_ID"],
        client_id=os.environ["KV_CLIENT_ID"],
        client_secret=os.environ["KV_CLIENT_SECRET"],
        authority="127.0.0.1:8443",
        disable_instance_discovery=True,
    )
    client = SecretClient(
        vault_url="https://127.0.0.1:8443",
        credential=credential,
        verify_challenge_resource=False,
    )

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
