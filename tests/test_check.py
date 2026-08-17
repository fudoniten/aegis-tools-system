"""Tests for `aegis check` — the drift reconciler."""

from pathlib import Path

from typer.testing import CliRunner

from aegis import admin, cli_check, config, crypto, host_secrets, realm as realm_mod
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _messages(report) -> str:
    return "\n".join(f.message for f in report.findings)


def _errors(report) -> str:
    return "\n".join(f.message for f in report.errors)


def test_clean_repo_has_no_errors(repo: config.SecretsRepo):
    report = cli_check.run_check(repo)
    assert report.errors == []


def test_host_without_master_key(repo: config.SecretsRepo):
    repo.set_host_config(config.HostConfig(hostname="newhost"))

    report = cli_check.run_check(repo)

    assert "no master key set" in _errors(report)


def test_stale_deploy_output_for_removed_host(repo: config.SecretsRepo):
    """Deleting a host config leaves its secrets behind; check must say so."""
    stale = repo.host_deploy_path("decommissioned")
    stale.mkdir(parents=True)
    (stale / "nexus-key.age").write_text("x")

    report = cli_check.run_check(repo)

    assert "no config in src/hosts/" in _errors(report)


def test_role_member_without_key_file(repo: config.SecretsRepo):
    add_host(repo, "rama")
    repo.set_role_config(config.RoleConfig(name="kdc", hosts=["rama"]))
    repo.role_key_path("kdc").write_text("x")
    repo.role_pubkey_path("kdc").parent.mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path("kdc").write_text("age1kdc")

    report = cli_check.run_check(repo)

    assert "without a key file" in _errors(report)


def test_role_key_held_by_non_member(repo: config.SecretsRepo):
    """A leftover role key is a live capability, not a cosmetic problem."""
    add_host(repo, "rama")
    repo.set_role_config(config.RoleConfig(name="kdc", hosts=[]))
    repo.role_key_path("kdc").write_text("x")
    repo.role_pubkey_path("kdc").parent.mkdir(parents=True, exist_ok=True)
    repo.role_pubkey_path("kdc").write_text("age1kdc")

    key_file = repo.host_role_key_path("rama", "kdc")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("x")

    report = cli_check.run_check(repo)

    assert "is not a member" in _errors(report)


def test_realm_with_no_declared_domains(repo: config.SecretsRepo):
    """The exact state that made build-keytabs a no-op."""
    repo.realm_principals_path("SEA.FUDO.ORG").mkdir(parents=True)
    realm_mod.save(repo, realm_mod.RealmConfig(name="SEA.FUDO.ORG"))

    report = cli_check.run_check(repo)

    assert "no domains declared" in _errors(report)


def test_realm_missing_kdc_role(repo: config.SecretsRepo):
    repo.realm_principals_path("SEA.FUDO.ORG").mkdir(parents=True)
    realm_mod.save(repo, realm_mod.RealmConfig(
        name="SEA.FUDO.ORG", domains=["sea.fudo.org"]))
    add_host(repo, "rama")
    repo.set_role_config(config.RoleConfig(
        name="domain-sea.fudo.org", hosts=["rama"]))

    report = cli_check.run_check(repo)

    assert "not be readable by the KDC" in _errors(report)


def test_declared_trust_without_stored_principal(repo: config.SecretsRepo):
    repo.realm_principals_path("A.ORG").mkdir(parents=True)
    realm_mod.save(repo, realm_mod.RealmConfig(
        name="A.ORG", domains=["a.org"], trusts=["B.ORG"]))
    add_host(repo, "hosta")
    repo.set_role_config(config.RoleConfig(name="domain-a.org", hosts=["hosta"]))

    report = cli_check.run_check(repo)

    assert "krbtgt/B.ORG@A.ORG is not stored" in _errors(report)


def test_user_secrets_left_on_revoked_host(repo: config.SecretsRepo):
    """Removing a host from a user's list does not delete deployed secrets."""
    repo.set_user_config(config.UserConfig(username="niten", hosts=["rama"]))
    repo.user_key_path("niten").parent.mkdir(parents=True, exist_ok=True)
    repo.user_key_path("niten").write_text("x")

    orphan = repo.host_deploy_path("oldhost") / "users" / "niten"
    orphan.mkdir(parents=True)
    (orphan / "manifest.age").write_text("x")

    report = cli_check.run_check(repo)

    assert "not in their host list" in _errors(report)


def test_single_admin_key_warns(repo: config.SecretsRepo):
    report = cli_check.run_check(repo)

    assert "only one admin key" in _messages(report)
    assert not any("only one admin key" in f.message for f in report.errors)


def test_second_admin_key_silences_warning(repo: config.SecretsRepo):
    admin.add_key(repo, crypto.generate_age_keypair().public_key, "backup")

    report = cli_check.run_check(repo)

    assert "only one admin key" not in _messages(report)


def test_legacy_build_dir_warns(tmp_path: Path, admin_key):
    legacy = config.SecretsRepo(tmp_path)
    (tmp_path / "build").mkdir()
    (tmp_path / "src" / "hosts").mkdir(parents=True)
    (tmp_path / "keys" / "admin").mkdir(parents=True)
    admin.add_key(legacy, admin_key.public_key, "primary")
    legacy = config.SecretsRepo(tmp_path)  # re-resolve deploy path

    report = cli_check.run_check(legacy)

    assert "reads as a regenerable artifact" in _messages(report)


def test_missing_manifest_entry_for_existing_secret(repo: config.SecretsRepo):
    add_host(repo, "rama")
    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    (deploy / "nexus-key.age").write_text("x")

    report = cli_check.run_check(repo)

    assert "no nexus-key entry" in _errors(report)


def test_recipient_shortfall_detected(repo: config.SecretsRepo, admin_key):
    """A file encrypted before an admin key was added is spotted by count."""
    keypair = add_host(repo, "rama")
    assert keypair is not None

    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    # Encrypted for the host only, missing the admin recipient
    crypto.encrypt_age("secret", [keypair.public_key], deploy / "nexus-key.age")

    manifest = host_secrets.HostSecretsManifest(hostname="rama")
    manifest.nexus_key = host_secrets.make_nexus_key_entry()
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    report = cli_check.run_check(repo)

    assert "missing a recipient" in _errors(report)


def test_check_command_exits_nonzero_on_errors(repo: config.SecretsRepo):
    repo.set_host_config(config.HostConfig(hostname="broken"))

    result = runner.invoke(app, ["check", "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert "no master key set" in result.stdout


def test_check_command_clean_exits_zero(repo: config.SecretsRepo):
    admin.add_key(repo, crypto.generate_age_keypair().public_key, "backup")

    result = runner.invoke(app, ["check", "--secrets-path", str(repo.path)])

    assert result.exit_code == 0
    assert "No problems found" in result.stdout


def test_reencrypt_repairs_recipient_drift(repo: config.SecretsRepo, admin_key):
    """The repair path for the drift `check` reports."""
    keypair = add_host(repo, "rama")
    assert keypair is not None

    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    target = deploy / "nexus-key.age"
    crypto.encrypt_age("ddns-secret", [keypair.public_key], target)

    assert crypto.recipients_of(target) == 1
    # The admin cannot read it yet, which is why reencrypt has to be run from
    # a machine holding a key that can.
    crypto.encrypt_age("ddns-secret", [keypair.public_key, admin_key.public_key], target)

    backup = crypto.generate_age_keypair()
    admin.add_key(repo, backup.public_key, "backup")

    result = runner.invoke(app, ["reencrypt", "--secrets-path", str(repo.path), "--yes"])

    assert result.exit_code == 0, result.stdout
    assert crypto.recipients_of(target) == 3
    assert crypto.decrypt_age(target, identity_content=backup.private_key) == "ddns-secret"


def test_reencrypt_preserves_plaintext(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None

    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    target = deploy / "nexus-key.age"
    crypto.encrypt_age(b"\x00\xffbinary", [keypair.public_key, admin_key.public_key], target)

    admin.add_key(repo, crypto.generate_age_keypair().public_key, "backup")
    runner.invoke(app, ["reencrypt", "--secrets-path", str(repo.path), "--yes"])

    assert crypto.decrypt_age_bytes(
        target, identity_content=keypair.private_key) == b"\x00\xffbinary"


def test_reencrypt_rebuilds_manifest_from_placement(
    repo: config.SecretsRepo, admin_key
):
    """A target path changed in src/ reaches the manifest without regenerating keys."""
    keypair = add_host(repo, "rama")
    assert keypair is not None

    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    crypto.encrypt_age(
        "kt", [keypair.public_key, admin_key.public_key], deploy / "keytab.age")

    host_config = repo.get_host_config("rama")
    assert host_config is not None
    host_config.set_placement("keytab", config.Placement(
        target="/etc/krb5.keytab", mode="0600"))
    repo.set_host_config(host_config)

    runner.invoke(app, ["reencrypt", "--secrets-path", str(repo.path), "--yes"])

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "rama")
    assert manifest.keytab is not None
    assert manifest.keytab.target == "/etc/krb5.keytab"


def test_reencrypt_dry_run_changes_nothing(repo: config.SecretsRepo, admin_key):
    keypair = add_host(repo, "rama")
    assert keypair is not None

    deploy = repo.host_deploy_path("rama")
    deploy.mkdir(parents=True)
    target = deploy / "nexus-key.age"
    crypto.encrypt_age("x", [keypair.public_key, admin_key.public_key], target)
    before = target.read_bytes()

    admin.add_key(repo, crypto.generate_age_keypair().public_key, "backup")
    result = runner.invoke(
        app, ["reencrypt", "--secrets-path", str(repo.path), "--dry-run"])

    assert result.exit_code == 0
    assert target.read_bytes() == before


def test_orphaned_role_file_detected(repo: config.SecretsRepo):
    """Renaming a role leaves its old key material behind, still usable."""
    roles_dir = repo.roles_deploy_path()
    roles_dir.mkdir(parents=True)
    (roles_dir / "dns-fudo.org.age").write_text("x")

    repo.set_role_config(config.RoleConfig(name="dns-master-fudo.org", hosts=[]))
    repo.role_key_path("dns-master-fudo.org").write_text("x")
    repo.role_pubkey_path("dns-master-fudo.org").write_text("age1x")

    report = cli_check.run_check(repo)

    assert "no matching config in src/roles/" in _messages(report)


def test_unfinished_rotation_is_reported(repo: config.SecretsRepo):
    """A retained pre-rekey key means the old key is still valid."""
    repo.realm_principals_path("A.ORG").mkdir(parents=True)
    realm_mod.save(repo, realm_mod.RealmConfig(name="A.ORG", domains=["a.org"]))
    add_host(repo, "hosta")
    repo.set_role_config(config.RoleConfig(name="domain-a.org", hosts=["hosta"]))
    previous = repo.realm_previous_principals_path("A.ORG")
    previous.mkdir(parents=True)
    (previous / "host_hosta.a.org.age").write_text("x")

    report = cli_check.run_check(repo)

    assert "mid-rotation" in _messages(report)
    assert "--prune" in "\n".join(f.hint or "" for f in report.findings)


# =============================================================================
# [[ssh-host-keys]] hygiene
# =============================================================================

def _misfiled_manifest(repo: config.SecretsRepo, hostname: str) -> None:
    """A host whose deploy and initrd keys were swept in with the host keys."""
    ssh_dir = repo.host_deploy_path(hostname) / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    for stem in (
        "ssh_host_ed25519_key",
        "ssh_host_ecdsa_key",
        "deploy_ed25519_key",
        "initrd_ed25519_key",
    ):
        (ssh_dir / f"{stem}.age").write_text("x")

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    manifest.ssh_host_keys = [
        host_secrets.SecretEntry(
            source=f"ssh/{stem}.age",
            target=stem,
            target_dir="/run/aegis/ssh",
            mode="0600",
            type=key_type,
        )
        for stem, key_type in [
            ("ssh_host_ed25519_key", "ed25519"),
            ("ssh_host_ecdsa_key", "ecdsa"),
            ("deploy_ed25519_key", "deploy_ed25519"),
            ("initrd_ed25519_key", "initrd_ed25519"),
        ]
    ]
    host_secrets.save_host_manifest(repo.deploy_path, manifest)


def test_non_sshd_key_type_is_an_error(repo: config.SecretsRepo):
    """nomenclator-0's shape: deploy and initrd keys typed as host keys."""
    add_host(repo, "nomenclator-0")
    _misfiled_manifest(repo, "nomenclator-0")

    report = cli_check.run_check(repo)

    errors = _errors(report)
    assert "deploy_ed25519_key as type deploy_ed25519" in errors
    assert "initrd_ed25519_key as type initrd_ed25519" in errors


def test_duplicate_key_type_is_an_error(repo: config.SecretsRepo):
    """forge's shape: several ed25519 keys all typed ed25519."""
    add_host(repo, "forge")
    ssh_dir = repo.host_deploy_path("forge") / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "ssh_host_ed25519_key.age").write_text("x")
    (ssh_dir / "deploy_ed25519_key.age").write_text("x")

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "forge")
    manifest.ssh_host_keys = [
        host_secrets.SecretEntry(
            source=f"ssh/{stem}.age", target=stem, type="ed25519")
        for stem in ("ssh_host_ed25519_key", "deploy_ed25519_key")
    ]
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    report = cli_check.run_check(repo)

    assert "repeats type(s) ed25519" in _errors(report)


def test_refresh_manifest_repairs_a_misfiled_host(repo: config.SecretsRepo):
    """The non-destructive repair: rebuild from disk, regenerating no key."""
    add_host(repo, "nomenclator-0")
    _misfiled_manifest(repo, "nomenclator-0")

    cli_check._refresh_manifest(repo, "nomenclator-0")

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nomenclator-0")

    assert sorted(e.target for e in manifest.ssh_host_keys) == [
        "ssh_host_ecdsa_key", "ssh_host_ed25519_key"]
    assert sorted(e.type for e in manifest.ssh_host_keys) == ["ecdsa", "ed25519"]

    # The deploy and initrd keys are still deployed -- to the same path -- but
    # no longer as sshd identities.
    assert manifest.secrets["deploy-ed25519-key"].target == (
        "/run/aegis/ssh/deploy_ed25519_key")
    assert manifest.secrets["initrd-ed25519-key"].type is None

    assert cli_check.run_check(repo).errors == []
