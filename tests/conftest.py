"""Shared fixtures.

Most commands now encrypt for the repo's admin recipient set and refuse to run
if the local key is not part of it, so tests need both an admin identity and a
repo that knows about it.
"""

import shutil
from pathlib import Path

import pytest

from aegis import admin, config, crypto


def requires(*binaries: str):
    """Skip a test when an external tool is unavailable."""
    missing = [b for b in binaries if shutil.which(b) is None]
    return pytest.mark.skipif(
        bool(missing), reason=f"requires {', '.join(missing)}"
    )


@pytest.fixture
def admin_key(tmp_path_factory, monkeypatch) -> crypto.AgeKeypair:
    """An admin identity at the default location, isolated per test session."""
    home = tmp_path_factory.mktemp("admin-home")
    monkeypatch.setenv("HOME", str(home))

    keypair = crypto.generate_age_keypair()
    key_path = home / ".config" / "aegis" / "key.txt"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(keypair.private_key + "\n")
    key_path.chmod(0o600)

    return keypair


@pytest.fixture
def repo(tmp_path: Path, admin_key: crypto.AgeKeypair) -> config.SecretsRepo:
    """An initialised secrets repo whose admin set contains the local key."""
    secrets_repo = config.SecretsRepo(tmp_path)
    secrets_repo.ensure_structure()
    admin.add_key(secrets_repo, admin_key.public_key, "primary")
    return secrets_repo


@pytest.fixture
def repo_path(repo: config.SecretsRepo) -> Path:
    """Path to an initialised secrets repo, for CLI invocations."""
    return repo.path


def add_host(
    repo: config.SecretsRepo,
    hostname: str,
    *,
    pubkey: str | None = None,
    services: list[str] | None = None,
) -> crypto.AgeKeypair | None:
    """Register a host, generating a master keypair unless one is given."""
    keypair = None
    if pubkey is None:
        keypair = crypto.generate_age_keypair()
        pubkey = keypair.public_key

    repo.set_host_config(config.HostConfig(
        hostname=hostname,
        age_pubkey=pubkey,
        services=services or ["host", "ssh"],
    ))
    return keypair
