from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure_keyvault_docker.certs import ensure_localhost_certificate
from azure_keyvault_docker.config import get_settings


ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = ROOT / ".local-data" / "secrets.json"
SERVER_CERT_FILE = ROOT / ".local-certs" / "localhost.pem"
SERVER_KEY_FILE = ROOT / ".local-certs" / "localhost-key.pem"

TEST_TENANT_ID = "11111111-2222-3333-4444-555555555555"
TEST_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TEST_CLIENT_SECRET = "local-dev-secret"


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_server(port: int) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            response = httpx.get(f"https://127.0.0.1:{port}/", verify=False)
            if response.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("server did not start")


def launch_emulator(env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "azure_keyvault_docker"],
        cwd=ROOT,
        env=env,
    )


def make_python_client(port: int) -> SecretClient:
    credential = ClientSecretCredential(
        tenant_id=TEST_TENANT_ID,
        client_id=TEST_CLIENT_ID,
        client_secret=TEST_CLIENT_SECRET,
        authority=f"127.0.0.1:{port}",
        disable_instance_discovery=True,
        additionally_allowed_tenants=["*"],
        connection_verify=False,
    )
    return SecretClient(
        vault_url=f"https://127.0.0.1:{port}",
        credential=credential,
        verify_challenge_resource=False,
        connection_verify=False,
    )


@pytest.fixture(scope="session")
def emulator():
    port = reserve_port()
    for cert_path in (SERVER_CERT_FILE, SERVER_KEY_FILE):
        if cert_path.exists():
            cert_path.unlink()
    ensure_localhost_certificate(get_settings())
    if STATE_FILE.exists():
        STATE_FILE.unlink()

    env = os.environ.copy()
    env["EMULATOR_PORT"] = str(port)
    env["EMULATOR_ISSUER_PORT"] = str(port)
    process = launch_emulator(env)
    try:
        wait_for_server(port)
        yield {"process": process, "env": env, "port": port}
    finally:
        process.terminate()
        process.wait(timeout=10)
