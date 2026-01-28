"""Tests for CLI commands."""

import pytest
from pathlib import Path
from typer.testing import CliRunner

from aegis.cli import app
from aegis import config


runner = CliRunner()


@pytest.fixture
def temp_secrets_repo(tmp_path: Path) -> Path:
    """Create a temporary secrets repo structure."""
    repo = config.SecretsRepo(tmp_path)
    repo.ensure_structure()
    return tmp_path


def test_status_empty_repo(temp_secrets_repo: Path):
    """Status command works on empty repo."""
    result = runner.invoke(app, ["status", "--secrets-path", str(temp_secrets_repo)])
    
    assert result.exit_code == 0
    assert "Configured hosts: 0" in result.stdout


def test_init_host(temp_secrets_repo: Path):
    """Initialize a host."""
    result = runner.invoke(app, [
        "init-host", "testhost",
        "--secrets-path", str(temp_secrets_repo),
        "--services", "host,ssh,nfs"
    ])
    
    assert result.exit_code == 0
    assert "Initialized host: testhost" in result.stdout
    
    # Verify config was created
    repo = config.SecretsRepo(temp_secrets_repo)
    host_config = repo.get_host_config("testhost")
    assert host_config is not None
    assert host_config.services == ["host", "ssh", "nfs"]


def test_init_host_duplicate(temp_secrets_repo: Path):
    """Cannot initialize same host twice."""
    runner.invoke(app, ["init-host", "testhost", "--secrets-path", str(temp_secrets_repo)])
    result = runner.invoke(app, ["init-host", "testhost", "--secrets-path", str(temp_secrets_repo)])
    
    assert result.exit_code == 1
    assert "already configured" in result.stdout


def test_add_user(temp_secrets_repo: Path):
    """Add a user with keypair generation."""
    result = runner.invoke(app, [
        "add-user", "alice",
        "--hosts", "server1,server2",
        "--secrets-path", str(temp_secrets_repo),
    ])
    
    assert result.exit_code == 0
    assert "Added user: alice" in result.stdout
    assert "age1" in result.stdout  # Public key should be shown
    
    # Verify config was created
    repo = config.SecretsRepo(temp_secrets_repo)
    user_config = repo.get_user_config("alice")
    assert user_config is not None
    assert user_config.hosts == ["server1", "server2"]
    
    # Verify encrypted key was created
    assert repo.user_key_path("alice").exists()


def test_list_empty(temp_secrets_repo: Path):
    """List command on empty repo."""
    result = runner.invoke(app, ["list", "--secrets-path", str(temp_secrets_repo)])
    
    assert result.exit_code == 0


def test_list_with_host(temp_secrets_repo: Path):
    """List command with a host."""
    # Initialize a host first
    runner.invoke(app, ["init-host", "testhost", "--secrets-path", str(temp_secrets_repo)])
    
    result = runner.invoke(app, ["list", "testhost", "--secrets-path", str(temp_secrets_repo)])
    
    assert result.exit_code == 0
    assert "testhost" in result.stdout
