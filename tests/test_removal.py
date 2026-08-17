"""Tests for `aegis <thing> list` and `aegis <thing> delete`.

Deletion refuses rather than cascading, so most of what is worth asserting is
what it declines to do and why.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis import config, host_secrets, removal
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _invoke(repo: config.SecretsRepo, *args: str):
    return runner.invoke(app, [*args, "--secrets-path", str(repo.path)])


def _role(repo: config.SecretsRepo, name: str, hosts: list[str]) -> None:
    """A role with a key file, a public key and members."""
    repo.set_role_config(config.RoleConfig(name=name, hosts=hosts))
    repo.role_key_path(name).parent.mkdir(parents=True, exist_ok=True)
    repo.role_key_path(name).write_text("role-key")
    repo.role_pubkey_path(name).parent.mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path(name).write_text("age1role")
    for host in hosts:
        key = repo.host_role_key_path(host, name)
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text("host-copy")


def _manifest(repo: config.SecretsRepo, host: str, **kwargs):
    manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
    for key, value in kwargs.items():
        setattr(manifest, key, value)
    host_secrets.save_host_manifest(repo.deploy_path, manifest)
    return manifest


# =============================================================================
# Listing
# =============================================================================

def test_role_list_shows_members_and_secrets(repo: config.SecretsRepo):
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])
    repo.role_secret_path("kdc", "ldap-bind").parent.mkdir(parents=True, exist_ok=True)
    repo.role_secret_path("kdc", "ldap-bind").write_text("x")

    result = _invoke(repo, "role", "list")

    assert result.exit_code == 0
    assert "kdc" in result.output
    assert "rama" in result.output
    assert "ldap-bind" in result.output


def test_role_list_on_empty_repo_says_how_to_make_one(repo: config.SecretsRepo):
    result = _invoke(repo, "role", "list")

    assert result.exit_code == 0
    assert "aegis role init" in result.output


def test_host_list_flags_a_host_with_no_key(repo: config.SecretsRepo):
    repo.set_host_config(config.HostConfig(hostname="keyless"))

    result = _invoke(repo, "host", "list")

    assert "keyless" in result.output
    assert "NO KEY" in result.output


def test_host_list_filters_by_status(repo: config.SecretsRepo):
    add_host(repo, "live")
    repo.set_host_config(
        config.HostConfig(hostname="gone", status=config.STATUS_RETIRED))

    result = _invoke(repo, "host", "list", "--status", "retired")

    assert "gone" in result.output
    assert "live" not in result.output


def test_ssh_list_separates_sshd_keys_from_delivered_ones(repo: config.SecretsRepo):
    add_host(repo, "rama")
    _manifest(
        repo, "rama",
        ssh_host_keys=host_secrets.make_ssh_host_keys_entries(
            stems=["ssh_host_ed25519_key"], key_types=["ed25519"]),
        secrets=host_secrets.make_ssh_auxiliary_entries(
            stems=["deploy_ed25519_key"]),
    )

    result = _invoke(repo, "ssh", "list", "rama")

    assert "sshd" in result.output
    assert "ssh_host_ed25519_key" in result.output
    assert "[secrets] deploy-ed25519-key" in result.output


# =============================================================================
# Deletion refuses while something still points at the thing
# =============================================================================

def test_role_delete_refuses_while_a_manifest_declares_its_secrets(
    repo: config.SecretsRepo,
):
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])
    _manifest(repo, "rama", roles=["kdc"], secrets={
        "ldap-bind": host_secrets.SecretEntry(
            source="../../roles/kdc/secrets/ldap-bind.age",
            target="/run/ldap/bind", role="kdc"),
    })

    result = _invoke(repo, "role", "delete", "kdc", "--yes")

    assert result.exit_code == 1
    assert "Refusing to delete" in result.output
    assert "ldap-bind" in result.output
    # Nothing touched.
    assert repo.role_key_path("kdc").exists()
    assert repo.get_role_config("kdc") is not None


def test_role_delete_groups_the_hosts_that_block_it(repo: config.SecretsRepo):
    """One decision, not one line per member."""
    hosts = [f"node-{i}" for i in range(5)]
    for host in hosts:
        add_host(repo, host)
        _manifest(repo, host, secrets={
            "token": host_secrets.SecretEntry(
                source="../../roles/app/secrets/token.age",
                target="/run/token", role="app"),
        })
    _role(repo, "app", hosts)

    plan = removal.plan_role_removal(repo, "app")

    blocking = [b for b in plan.blockers if "manifest" in b]
    assert len(blocking) == 1
    assert "5 host manifest(s)" in blocking[0]


def test_role_delete_removes_key_members_and_host_copies(repo: config.SecretsRepo):
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])
    _manifest(repo, "rama", roles=["kdc"])

    result = _invoke(repo, "role", "delete", "kdc", "--yes")

    assert result.exit_code == 0
    assert repo.get_role_config("kdc") is None
    assert not repo.role_key_path("kdc").exists()
    assert not repo.role_pubkey_path("kdc").exists()
    assert not repo.host_role_key_path("rama", "kdc").exists()
    # The member's manifest stops claiming a role it no longer holds.
    assert host_secrets.load_host_manifest(repo.deploy_path, "rama").roles == []


def test_host_delete_refuses_while_active_with_secrets(repo: config.SecretsRepo):
    add_host(repo, "rama")
    deploy = repo.host_deploy_path("rama")
    (deploy / "secrets").mkdir(parents=True)
    (deploy / "secrets" / "token.age").write_text("x")

    result = _invoke(repo, "host", "delete", "rama", "--yes")

    assert result.exit_code == 1
    assert "set-status rama retired" in result.output
    assert repo.get_host_config("rama") is not None


def test_host_delete_refuses_while_a_role_lists_it(repo: config.SecretsRepo):
    add_host(repo, "rama")
    repo.set_host_config(
        config.HostConfig(hostname="rama", status=config.STATUS_RETIRED))
    _role(repo, "kdc", ["rama"])

    result = _invoke(repo, "host", "delete", "rama", "--yes")

    assert result.exit_code == 1
    assert "role 'kdc' still lists it" in result.output


def test_host_delete_proceeds_once_nothing_refers_to_it(repo: config.SecretsRepo):
    repo.set_host_config(
        config.HostConfig(hostname="gone", status=config.STATUS_RETIRED))
    repo.host_deploy_path("gone").mkdir(parents=True)

    result = _invoke(repo, "host", "delete", "gone", "--yes")

    assert result.exit_code == 0
    assert repo.get_host_config("gone") is None
    assert not repo.host_deploy_path("gone").exists()


def test_force_overrides_a_blocker(repo: config.SecretsRepo):
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])
    _manifest(repo, "rama", secrets={
        "ldap-bind": host_secrets.SecretEntry(
            source="../../roles/kdc/secrets/ldap-bind.age",
            target="/run/ldap/bind", role="kdc"),
    })

    result = _invoke(repo, "role", "delete", "kdc", "--yes", "--force")

    assert result.exit_code == 0
    assert "--force given" in result.output
    assert repo.get_role_config("kdc") is None


def test_dry_run_changes_nothing(repo: config.SecretsRepo):
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])

    result = _invoke(repo, "role", "delete", "kdc", "--dry-run")

    assert result.exit_code == 0
    assert "[dry-run]" in result.output
    assert repo.role_key_path("kdc").exists()


def test_deleting_something_that_is_not_there_fails(repo: config.SecretsRepo):
    result = _invoke(repo, "role", "delete", "nonexistent", "--yes")

    assert result.exit_code == 1
    assert "Nothing to remove" in result.output


# =============================================================================
# The rest of the categories
# =============================================================================

def test_secret_delete_covers_every_recipient_by_default(repo: config.SecretsRepo):
    """Deleting from one host and leaving three is the failure to avoid."""
    for host in ("rama", "arx"):
        add_host(repo, host)
        secrets_dir = repo.host_deploy_path(host) / "secrets"
        secrets_dir.mkdir(parents=True)
        (secrets_dir / "token.age").write_text("x")
        _manifest(repo, host, secrets={
            "token": host_secrets.make_secret_entry("token"),
        })

    result = _invoke(repo, "secret", "delete", "token", "--yes")

    assert result.exit_code == 0
    for host in ("rama", "arx"):
        assert not (repo.host_deploy_path(host) / "secrets" / "token.age").exists()
        assert "token" not in host_secrets.load_host_manifest(
            repo.deploy_path, host).secrets


def test_secret_delete_can_be_scoped_to_one_host(repo: config.SecretsRepo):
    for host in ("rama", "arx"):
        add_host(repo, host)
        secrets_dir = repo.host_deploy_path(host) / "secrets"
        secrets_dir.mkdir(parents=True)
        (secrets_dir / "token.age").write_text("x")

    result = _invoke(repo, "secret", "delete", "token", "--host", "rama", "--yes")

    assert result.exit_code == 0
    assert not (repo.host_deploy_path("rama") / "secrets" / "token.age").exists()
    assert (repo.host_deploy_path("arx") / "secrets" / "token.age").exists()


def test_ssh_delete_clears_both_manifest_sections(repo: config.SecretsRepo):
    add_host(repo, "rama")
    ssh_dir = repo.host_deploy_path("rama") / "ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "ssh_host_ed25519_key.age").write_text("x")
    _manifest(
        repo, "rama",
        ssh_host_keys=host_secrets.make_ssh_host_keys_entries(
            stems=["ssh_host_ed25519_key"], key_types=["ed25519"]),
        secrets=host_secrets.make_ssh_auxiliary_entries(
            stems=["deploy_ed25519_key"]),
    )

    result = _invoke(repo, "ssh", "delete", "rama", "--yes")

    assert result.exit_code == 0
    assert "known_hosts" in result.output
    manifest = host_secrets.load_host_manifest(repo.deploy_path, "rama")
    assert manifest.ssh_host_keys == []
    assert manifest.secrets == {}
    assert not ssh_dir.exists()


def test_nexus_delete_clears_the_manifest_entry(repo: config.SecretsRepo):
    add_host(repo, "rama")
    (repo.host_deploy_path("rama")).mkdir(parents=True, exist_ok=True)
    (repo.host_deploy_path("rama") / "nexus-key.age").write_text("x")
    _manifest(repo, "rama", nexus_key=host_secrets.make_nexus_key_entry())

    result = _invoke(repo, "nexus", "delete", "rama", "--yes")

    assert result.exit_code == 0
    assert host_secrets.load_host_manifest(repo.deploy_path, "rama").nexus_key is None


def test_dnssec_delete_refuses_while_the_role_has_signers(repo: config.SecretsRepo):
    add_host(repo, "aedile")
    repo.dnssec_src_path("fudo.org").mkdir(parents=True)
    _role(repo, "dns-master-fudo.org", ["aedile"])

    result = _invoke(repo, "dnssec", "delete", "fudo.org", "--yes")

    assert result.exit_code == 1
    assert "dns-master-fudo.org" in result.output
    assert repo.dnssec_src_path("fudo.org").exists()


def test_nebula_delete_refuses_while_hosts_are_on_the_network(
    repo: config.SecretsRepo,
):
    add_host(repo, "rama")
    repo.nebula_hosts_path("fudo").mkdir(parents=True)
    repo.nebula_host_config_path("fudo", "rama").write_text("ip = '10.0.0.1'")

    result = _invoke(repo, "nebula", "delete", "fudo", "--yes")

    assert result.exit_code == 1
    assert "still on it: rama" in result.output
    assert repo.nebula_network_path("fudo").exists()


def test_nebula_delete_host_leaves_the_network(repo: config.SecretsRepo):
    add_host(repo, "rama")
    repo.nebula_hosts_path("fudo").mkdir(parents=True)
    repo.nebula_host_config_path("fudo", "rama").write_text("ip = '10.0.0.1'")

    result = _invoke(repo, "nebula", "delete-host", "fudo", "rama", "--yes")

    assert result.exit_code == 0
    assert not repo.nebula_host_config_path("fudo", "rama").exists()
    assert repo.nebula_network_path("fudo").exists()
    assert "aegis build nebula" in result.output


def test_realm_delete_refuses_while_principals_are_declared(
    repo: config.SecretsRepo,
):
    repo.realm_principals_path("SEA.FUDO.ORG").mkdir(parents=True)
    (repo.realm_principals_path("SEA.FUDO.ORG") / "host.toml").write_text("x")

    result = _invoke(repo, "realm", "delete", "SEA.FUDO.ORG", "--yes")

    assert result.exit_code == 1
    assert "principal(s) are still declared" in result.output
    assert repo.realm_path("SEA.FUDO.ORG").exists()


def test_user_delete_removes_key_and_per_host_copies(repo: config.SecretsRepo):
    add_host(repo, "rama")
    repo.user_key_path("niten").parent.mkdir(parents=True, exist_ok=True)
    repo.user_key_path("niten").write_text("x")
    repo.user_pubkey_path("niten").write_text("age1user")
    user_dir = repo.host_deploy_path("rama") / "users" / "niten"
    user_dir.mkdir(parents=True)
    (user_dir / "manifest.age").write_text("x")

    result = _invoke(repo, "user", "delete", "niten", "--yes")

    assert result.exit_code == 0
    assert not repo.user_key_path("niten").exists()
    assert not user_dir.exists()


def test_a_blocked_plan_leaves_the_repo_untouched(repo: config.SecretsRepo):
    """The planners must not mutate; only apply() may."""
    add_host(repo, "rama")
    _role(repo, "kdc", ["rama"])
    _manifest(repo, "rama", roles=["kdc"])

    before = sorted(p.name for p in repo.path.rglob("*") if p.is_file())
    removal.plan_role_removal(repo, "kdc")
    after = sorted(p.name for p in repo.path.rglob("*") if p.is_file())

    assert before == after
