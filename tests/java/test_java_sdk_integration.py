from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


from conftest import TEST_CLIENT_ID, TEST_CLIENT_SECRET, TEST_TENANT_ID


JAVA_TEST_ROOT = Path(__file__).resolve().parent


def test_java_sdk_secret_flows(emulator):
    env = os.environ.copy()
    env.update(
        {
            "KEYVAULT_EMULATOR_HOST": "127.0.0.1",
            "KEYVAULT_EMULATOR_PORT": str(emulator["port"]),
            "KEYVAULT_TENANT_ID": TEST_TENANT_ID,
            "KEYVAULT_CLIENT_ID": TEST_CLIENT_ID,
            "KEYVAULT_CLIENT_SECRET": TEST_CLIENT_SECRET,
        }
    )
    subprocess.run(
        [sys.executable, str(JAVA_TEST_ROOT / "run_maven.py"), "-q", "test"],
        cwd=JAVA_TEST_ROOT,
        env=env,
        check=True,
    )
