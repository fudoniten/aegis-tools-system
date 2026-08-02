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
    assert (tmp_path / "src" / "roles").exists()
    assert (tmp_path / "src" / "users").exists()
    assert (tmp_path / "src" / "kerberos" / "realms").exists()
    assert (tmp_path / "keys" / "admin").exists()
    assert (tmp_path / "keys" / "users").exists()
    assert (tmp_path / "keys" / "roles").exists()
    assert (tmp_path / "deploy").exists()


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
    """Save and load role configuration with multiple hosts."""
    role_config = config.RoleConfig(
        name="kdc",
        hosts=["kdc-server", "kdc-replica"],
    )

    temp_repo.set_role_config(role_config)
    loaded = temp_repo.get_role_config("kdc")

    assert loaded is not None
    assert loaded.name == "kdc"
    assert loaded.hosts == ["kdc-server", "kdc-replica"]


def test_role_config_backward_compat(temp_repo: config.SecretsRepo):
    """Old single-host role TOML files are read correctly."""
    import tomli_w
    role_path = temp_repo.src_path / "roles" / "dns.toml"
    role_path.parent.mkdir(parents=True, exist_ok=True)
    with open(role_path, "wb") as f:
        tomli_w.dump({"host": "polaris"}, f)

    loaded = temp_repo.get_role_config("dns")
    assert loaded is not None
    assert loaded.hosts == ["polaris"]


def test_role_config_empty_hosts(temp_repo: config.SecretsRepo):
    """Role config with empty hosts list."""
    role_config = config.RoleConfig(name="backup", hosts=[])
    temp_repo.set_role_config(role_config)
    loaded = temp_repo.get_role_config("backup")
    assert loaded is not None
    assert loaded.hosts == []


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


def test_deploy_paths(temp_repo: config.SecretsRepo):
    """Get correct deploy output paths."""
    assert temp_repo.host_deploy_path("myhost") == temp_repo.path / "deploy" / "hosts" / "myhost"
    assert temp_repo.dnssec_deploy_path("example.com") == temp_repo.path / "deploy" / "dnssec" / "example_com"
    # Legacy alias keeps working
    assert temp_repo.host_build_path("myhost") == temp_repo.host_deploy_path("myhost")


def test_legacy_build_dir_is_honoured(tmp_path: Path):
    """A repo that still has build/ and no deploy/ keeps using build/."""
    (tmp_path / "build" / "hosts").mkdir(parents=True)
    repo = config.SecretsRepo(tmp_path)

    assert repo.uses_legacy_deploy_dir()
    assert repo.deploy_path == tmp_path / "build"
    assert repo.host_deploy_path("myhost") == tmp_path / "build" / "hosts" / "myhost"


def test_deploy_dir_preferred_when_both_exist(tmp_path: Path):
    """Once deploy/ exists it wins over a leftover build/."""
    (tmp_path / "build").mkdir()
    (tmp_path / "deploy").mkdir()
    repo = config.SecretsRepo(tmp_path)

    assert not repo.uses_legacy_deploy_dir()
    assert repo.deploy_path == tmp_path / "deploy"


def test_placement_roundtrip(temp_repo: config.SecretsRepo):
    """Placement survives a save/load cycle, so the manifest stays derived."""
    host_config = config.HostConfig(hostname="testhost")
    host_config.set_placement("keytab", config.Placement(
        target="/etc/krb5.keytab", mode="0600"))
    host_config.set_placement("secret:token", config.Placement(
        target="/run/svc/token", user="svc"))
    temp_repo.set_host_config(host_config)

    loaded = temp_repo.get_host_config("testhost")
    assert loaded is not None
    assert loaded.placement_for("keytab").target == "/etc/krb5.keytab"
    assert loaded.placement_for("keytab").mode == "0600"
    assert loaded.placement_for("secret:token").user == "svc"
    # Unset kinds come back empty rather than missing
    assert loaded.placement_for("nexus-key").is_empty()


def test_dnssec_domain_name_not_reversed_from_path(temp_repo: config.SecretsRepo):
    """Domain names come from the config file, not the mangled directory name."""
    temp_repo.set_dnssec_config(config.DnssecConfig(
        domain="sea.fudo.org", algorithm="ECDSAP256SHA256",
        algorithm_num=13, keytag=1234))

    assert temp_repo.list_dnssec_domains() == ["sea.fudo.org"]


def test_missing_config_returns_none(temp_repo: config.SecretsRepo):
    """Missing config returns None, not error."""
    assert temp_repo.get_host_config("nonexistent") is None
    assert temp_repo.get_user_config("nonexistent") is None
    assert temp_repo.get_role_config("nonexistent") is None
