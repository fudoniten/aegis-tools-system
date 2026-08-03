"""Tests for the recipient policy and whole-repo re-encryption.

The point of a second admin key is that losing the first one costs nothing.
That only holds if re-encryption reaches the material whose loss is
catastrophic: role private keys, user private keys, realm master keys and
every Kerberos principal, all of which are encrypted for the admin set and
nobody else.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis import admin, config, crypto, realm as realm_mod, recipients
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _plan(repo: config.SecretsRepo) -> dict[str, recipients.FilePolicy]:
    """Policy keyed by repo-relative path, for readable assertions."""
    keys = admin.recipients(repo)
    return {
        str(p.path.relative_to(repo.path)): p
        for p in recipients.plan(repo, keys)
    }


def _write_encrypted(path: Path, content: bytes, keys: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(content, keys, path)


# =============================================================================
# Policy
# =============================================================================

def test_role_private_key_is_admin_only(repo: config.SecretsRepo, admin_key):
    _write_encrypted(repo.role_key_path("kdc"), b"role-priv", [admin_key.public_key])

    policy = _plan(repo)["keys/roles/kdc.age"]

    assert policy.category == recipients.CAT_ADMIN_ONLY
    assert policy.recipients == [admin_key.public_key]


def test_user_private_key_is_admin_only(repo: config.SecretsRepo, admin_key):
    _write_encrypted(repo.user_key_path("niten"), b"user-priv", [admin_key.public_key])

    policy = _plan(repo)["keys/users/niten.age"]

    assert policy.category == recipients.CAT_ADMIN_ONLY


def test_realm_key_and_principals_are_admin_only(
    repo: config.SecretsRepo, admin_key
):
    realm_mod.save(repo, realm_mod.RealmConfig(name="A.ORG", domains=["a.org"]))
    _write_encrypted(repo.realm_key_path("A.ORG"), b"\x00\xffrealm", [admin_key.public_key])
    _write_encrypted(
        repo.realm_principals_path("A.ORG") / "host_x.a.org.age",
        b"principal-line", [admin_key.public_key])

    plan = _plan(repo)

    assert plan["src/kerberos/realms/A.ORG/realm.key.age"].category == (
        recipients.CAT_ADMIN_ONLY)
    assert plan["src/kerberos/realms/A.ORG/principals/host_x.a.org.age"].category == (
        recipients.CAT_ADMIN_ONLY)


def test_host_secret_is_host_plus_admin(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None
    _write_encrypted(
        repo.host_deploy_path("rama") / "nexus-key.age", b"k",
        [keypair.public_key, admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/rama/nexus-key.age"]

    assert policy.category == recipients.CAT_HOST
    assert set(policy.recipients) == {keypair.public_key, admin_key.public_key}


def test_keytab_includes_the_kdc_role(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None
    realm_mod.save(repo, realm_mod.RealmConfig(
        name="A.ORG", domains=["a.org"], kdc_role="kdc"))
    repo.realm_principals_path("A.ORG").mkdir(parents=True, exist_ok=True)
    repo.set_role_config(config.RoleConfig(name="domain-a.org", hosts=["rama"]))
    repo.role_pubkey_path("kdc").parent.mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path("kdc").write_text("age1kdcrole")

    _write_encrypted(
        repo.host_deploy_path("rama") / "keytab.age", b"kt",
        [keypair.public_key, admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/rama/keytab.age"]

    assert "age1kdcrole" in policy.recipients
    assert policy.expected_count == 3


def test_keytab_without_a_kdc_role_is_not_guessed(
    repo: config.SecretsRepo, admin_key
):
    """Better to refuse than to rewrite a keytab the KDC then cannot read."""
    keypair = add_host(repo, "rama")
    assert keypair is not None
    _write_encrypted(
        repo.host_deploy_path("rama") / "keytab.age", b"kt",
        [keypair.public_key, admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/rama/keytab.age"]

    assert not policy.resolvable
    assert "KDC role" in (policy.problem or "")


def test_user_manifest_includes_the_user(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None
    user_key = crypto.generate_age_keypair()
    repo.set_user_config(config.UserConfig(
        username="niten", hosts=["rama"], public_key=user_key.public_key))

    _write_encrypted(
        repo.host_deploy_path("rama") / "users" / "niten" / "manifest.age",
        b"manifest", [keypair.public_key, admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/rama/users/niten/manifest.age"]

    assert user_key.public_key in policy.recipients
    assert policy.category == recipients.CAT_USER


def test_host_role_key_copy_is_host_plus_admin(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None
    _write_encrypted(
        repo.host_role_key_path("rama", "kdc"), b"role-priv",
        [keypair.public_key, admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/rama/roles/kdc.age"]

    assert policy.category == recipients.CAT_ROLE
    assert set(policy.recipients) == {keypair.public_key, admin_key.public_key}


def test_kdc_bundle_targets_the_realm_role(repo: config.SecretsRepo, admin_key):
    realm_mod.save(repo, realm_mod.RealmConfig(
        name="A.ORG", domains=["a.org"], kdc_role="kdc"))
    repo.realm_principals_path("A.ORG").mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path("kdc").parent.mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path("kdc").write_text("age1kdcrole")

    _write_encrypted(
        repo.kdc_deploy_path() / "A.ORG-principals.age", b"bundle",
        [admin_key.public_key])
    _write_encrypted(
        repo.kdc_deploy_path() / "A.ORG-realm-key.age", b"rk",
        [admin_key.public_key])

    plan = _plan(repo)

    for name in ("A.ORG-principals.age", "A.ORG-realm-key.age"):
        policy = plan[f"deploy/kdc/{name}"]
        assert policy.category == recipients.CAT_KDC
        assert "age1kdcrole" in policy.recipients


def test_unknown_deploy_files_are_flagged_not_guessed(
    repo: config.SecretsRepo, admin_key
):
    """deploy/domains/ predates the current layout; its audience is unknowable."""
    _write_encrypted(
        repo.deploy_path / "domains" / "fudo.org" / "role-key.age",
        b"legacy", [admin_key.public_key])

    policy = _plan(repo)["deploy/domains/fudo.org/role-key.age"]

    assert policy.category == recipients.CAT_LEGACY
    assert not policy.resolvable


def test_host_without_master_key_is_not_guessed(repo: config.SecretsRepo, admin_key):
    repo.set_host_config(config.HostConfig(hostname="keyless"))
    _write_encrypted(
        repo.host_deploy_path("keyless") / "nexus-key.age", b"k",
        [admin_key.public_key])

    policy = _plan(repo)["deploy/hosts/keyless/nexus-key.age"]

    assert not policy.resolvable
    assert "no master key" in (policy.problem or "")


# =============================================================================
# Re-encryption reaches the admin-only material
# =============================================================================

@pytest.fixture
def populated(repo: config.SecretsRepo, admin_key) -> config.SecretsRepo:
    """A repo holding one file of each admin-critical kind."""
    keypair = add_host(repo, "rama")
    assert keypair is not None

    _write_encrypted(repo.role_key_path("kdc"), b"role-priv", [admin_key.public_key])
    _write_encrypted(repo.user_key_path("niten"), b"user-priv", [admin_key.public_key])

    realm_mod.save(repo, realm_mod.RealmConfig(name="A.ORG", domains=["a.org"]))
    _write_encrypted(
        repo.realm_key_path("A.ORG"), b"\x00\xffbinary-realm-key",
        [admin_key.public_key])
    _write_encrypted(
        repo.realm_principals_path("A.ORG") / "host_rama.a.org.age",
        b"principal-dump-line", [admin_key.public_key])

    _write_encrypted(
        repo.host_deploy_path("rama") / "nexus-key.age", b"ddns",
        [keypair.public_key, admin_key.public_key])

    return repo


def test_backup_admin_key_reaches_admin_only_material(
    populated: config.SecretsRepo, admin_key
):
    """The whole point: a new admin key must be able to read the critical set.

    Before this, reencrypt only walked deploy/hosts/, so role keys, user keys,
    realm keys and principals kept a single recipient and a "redundant" admin
    key was not redundant at all.
    """
    backup = crypto.generate_age_keypair()
    admin.add_key(populated, backup.public_key, "backup")

    result = runner.invoke(
        app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])
    assert result.exit_code == 0, result.stdout

    for path, expected in [
        (populated.role_key_path("kdc"), b"role-priv"),
        (populated.user_key_path("niten"), b"user-priv"),
        (populated.realm_key_path("A.ORG"), b"\x00\xffbinary-realm-key"),
        (populated.realm_principals_path("A.ORG") / "host_rama.a.org.age",
         b"principal-dump-line"),
    ]:
        assert crypto.decrypt_age_bytes(
            path, identity_content=backup.private_key) == expected, path


def test_original_admin_key_still_works_afterwards(
    populated: config.SecretsRepo, admin_key
):
    backup = crypto.generate_age_keypair()
    admin.add_key(populated, backup.public_key, "backup")

    runner.invoke(app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    assert crypto.decrypt_age_bytes(
        populated.role_key_path("kdc"),
        identity_content=admin_key.private_key) == b"role-priv"


def test_host_keeps_access_after_reencrypt(populated: config.SecretsRepo):
    """Adding an admin key must not lock the host out of its own secrets."""
    host_config = populated.get_host_config("rama")
    assert host_config is not None

    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")
    runner.invoke(app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    policy = _plan(populated)["deploy/hosts/rama/nexus-key.age"]
    assert host_config.age_pubkey in policy.recipients
    assert crypto.recipients_of(
        populated.host_deploy_path("rama") / "nexus-key.age") == 3


def test_reencrypt_is_idempotent(populated: config.SecretsRepo):
    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")

    runner.invoke(app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])
    before = populated.role_key_path("kdc").read_bytes()

    result = runner.invoke(
        app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    assert "already carries the expected recipients" in result.stdout
    assert populated.role_key_path("kdc").read_bytes() == before


def test_reencrypt_dry_run_writes_nothing(populated: config.SecretsRepo):
    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")
    before = populated.role_key_path("kdc").read_bytes()

    result = runner.invoke(
        app, ["reencrypt", "--secrets-path", str(populated.path), "--dry-run"])

    assert result.exit_code == 0
    assert populated.role_key_path("kdc").read_bytes() == before
    assert "[dry-run]" in result.stdout


def test_reencrypt_category_filter(populated: config.SecretsRepo):
    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")

    result = runner.invoke(app, [
        "reencrypt", "--secrets-path", str(populated.path),
        "--category", recipients.CAT_ADMIN_ONLY, "--yes",
    ])

    assert result.exit_code == 0
    # admin-only material rewritten...
    assert crypto.recipients_of(populated.role_key_path("kdc")) == 2
    # ...host material left for a separate pass
    assert crypto.recipients_of(
        populated.host_deploy_path("rama") / "nexus-key.age") == 2


def test_binary_realm_key_survives_reencrypt(populated: config.SecretsRepo):
    """Realm keys are kstash output, not text; a lossy round trip breaks Kerberos."""
    backup = crypto.generate_age_keypair()
    admin.add_key(populated, backup.public_key, "backup")

    runner.invoke(app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    assert crypto.decrypt_age_bytes(
        populated.realm_key_path("A.ORG"),
        identity_content=backup.private_key) == b"\x00\xffbinary-realm-key"


def test_check_reports_admin_only_shortfall(populated: config.SecretsRepo):
    """check and reencrypt agree: what one flags, the other repairs."""
    from aegis import cli_check

    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")

    report = cli_check.run_check(populated)
    messages = "\n".join(f.message for f in report.errors)
    assert "missing a recipient" in messages
    assert recipients.CAT_ADMIN_ONLY in "\n".join(f.scope for f in report.errors)

    runner.invoke(app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    report = cli_check.run_check(populated)
    assert not any("missing a recipient" in f.message for f in report.errors)


def test_undecryptable_file_reported_not_silently_skipped(
    populated: config.SecretsRepo
):
    """A file the local admin cannot read is a loud failure, not a no-op."""
    stranger = crypto.generate_age_keypair()
    _write_encrypted(
        populated.role_key_path("orphan"), b"unreachable", [stranger.public_key])

    admin.add_key(populated, crypto.generate_age_keypair().public_key, "backup")

    result = runner.invoke(
        app, ["reencrypt", "--secrets-path", str(populated.path), "--yes"])

    assert result.exit_code == 1
    assert "cannot decrypt" in result.stdout + str(result.stderr or "")
