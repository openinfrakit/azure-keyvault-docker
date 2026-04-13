from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path


MAVEN_VERSION = "3.9.9"
ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT / ".tools"
MAVEN_DIR = TOOLS_DIR / f"apache-maven-{MAVEN_VERSION}"


def _download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def _ensure_maven() -> Path:
    if MAVEN_DIR.exists():
        return MAVEN_DIR

    system = platform.system()
    if system == "Windows":
        archive = TOOLS_DIR / f"apache-maven-{MAVEN_VERSION}-bin.zip"
        url = f"https://archive.apache.org/dist/maven/maven-3/{MAVEN_VERSION}/binaries/{archive.name}"
        _download_file(url, archive)
        with zipfile.ZipFile(archive) as extracted:
            extracted.extractall(TOOLS_DIR)
    else:
        archive = TOOLS_DIR / f"apache-maven-{MAVEN_VERSION}-bin.tar.gz"
        url = f"https://archive.apache.org/dist/maven/maven-3/{MAVEN_VERSION}/binaries/{archive.name}"
        _download_file(url, archive)
        with tarfile.open(archive) as extracted:
            extracted.extractall(TOOLS_DIR)

    return MAVEN_DIR


def main() -> int:
    maven_home = _ensure_maven()
    executable = maven_home / "bin" / ("mvn.cmd" if platform.system() == "Windows" else "mvn")
    command = [str(executable), *sys.argv[1:]]
    completed = subprocess.run(command, cwd=Path(__file__).resolve().parent)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
