"""Tests for configuration management."""

import pytest
from pathlib import Path

from aegis import config


@pytest.fixture
def temp_repo(tmp_path: Path) -> config.SecretsRepo:
    """Create a temporary secrets repo."""
    repo = config.SecretsRepo(tmp_path)
    repo.ensure_structure()
    return repo


def test_ensure_structure(tmp_path: Path):
    """Ensure directory structure is created."""
    repo = config.SecretsRepo(tmp_path)
    repo.ensure_structure()
    
    assert (tmp_path / "src" / "hosts").exists()
    assert (tmp_path / "src" / "domains").exists()
    assert (tmp_path / "src" / "roles").exists()
    assert (tmp_path / "src" / "users").exists()
    assert (tmp_path / "keys" / "users").exists()
    assert (tmp_path / "build").exists()


def test_host_config_roundtrip(temp_repo: config.SecretsRepo):
    """Save and load host configuration."""
    host_config = config.HostConfig(
        hostname="testhost",
        services=["host", "ssh", "postgres"],
        filesystem_keys=["data", "backup"],
    )
    
    temp_repo.set_host_config(host_config)
    loaded = temp_repo.get_host_config("testhost")
    
    assert loaded is not None
    assert loaded.hostname == "testhost"
    assert loaded.services == ["host", "ssh", "postgres"]
    assert loaded.filesystem_keys == ["data", "backup"]


def test_user_config_roundtrip(temp_repo: config.SecretsRepo):
    """Save and load user configuration."""
    user_config = config.UserConfig(
        username="alice",
        hosts=["server1", "server2"],
        repo_url="https://github.com/alice/aegis-secrets-alice",
    )
    
    temp_repo.set_user_config(user_config)
    loaded = temp_repo.get_user_config("alice")
    
    assert loaded is not None
    assert loaded.username == "alice"
    assert loaded.hosts == ["server1", "server2"]
    assert loaded.repo_url == "https://github.com/alice/aegis-secrets-alice"


def test_role_config_roundtrip(temp_repo: config.SecretsRepo):
    """Save and load role configuration."""
    role_config = config.RoleConfig(
        name="kdc",
        host="kdc-server",
    )
    
    temp_repo.set_role_config(role_config)
    loaded = temp_repo.get_role_config("kdc")
    
    assert loaded is not None
    assert loaded.name == "kdc"
    assert loaded.host == "kdc-server"


def test_list_hosts(temp_repo: config.SecretsRepo):
    """List configured hosts."""
    assert temp_repo.list_hosts() == []
    
    temp_repo.set_host_config(config.HostConfig(hostname="host1"))
    temp_repo.set_host_config(config.HostConfig(hostname="host2"))
    
    hosts = temp_repo.list_hosts()
    assert sorted(hosts) == ["host1", "host2"]


def test_list_users(temp_repo: config.SecretsRepo):
    """List configured users."""
    assert temp_repo.list_users() == []
    
    temp_repo.set_user_config(config.UserConfig(username="alice", hosts=["h1"]))
    temp_repo.set_user_config(config.UserConfig(username="bob", hosts=["h2"]))
    
    users = temp_repo.list_users()
    assert sorted(users) == ["alice", "bob"]


def test_build_paths(temp_repo: config.SecretsRepo):
    """Get correct build output paths."""
    assert temp_repo.host_build_path("myhost") == temp_repo.path / "build" / "hosts" / "myhost"
    assert temp_repo.domain_build_path("example.com") == temp_repo.path / "build" / "domains" / "example_com"


def test_missing_config_returns_none(temp_repo: config.SecretsRepo):
    """Missing config returns None, not error."""
    assert temp_repo.get_host_config("nonexistent") is None
    assert temp_repo.get_user_config("nonexistent") is None
    assert temp_repo.get_role_config("nonexistent") is None
