"""Secrets that belong to a role rather than to a machine.

The behaviour being pinned down: one ciphertext per role secret, encrypted to
the role, referenced by every member's manifest. That is what makes moving a
service between hosts a membership change rather than a re-import — so the
tests here mostly assert about *who declares what*, and about the fact that
the ciphertext does not change when membership does.
"""

from pathlib import Path

from typer.testing import CliRunner

from aegis import cli_check, config, crypto, host_secrets
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _written(tmp_path: Path, name: str, content: str) -> Path:
    source = tmp_path / f"{name}.plain"
    source.write_text(content)
    return source


def _import(repo_path: Path, name: str, content: str, tmp_path: Path, *args: str):
    return runner.invoke(app, [
        "secret", "import", name,
        "--file", str(_written(tmp_path, name, content)),
        "--target", f"/run/svc/{name}",
        *args,
        "--secrets-path", str(repo_path),
    ])


def _member(repo: config.SecretsRepo, role: str, hostname: str) -> crypto.AgeKeypair:
    """Register a host, give it a master key, and put it in the role."""
    keypair = add_host(repo, hostname)
    assert keypair is not None
    result = runner.invoke(app, [
        "role", "add-host", role, hostname,
        "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)
    return keypair


def _init_role(repo: config.SecretsRepo, role: str) -> None:
    result = runner.invoke(app, [
        "role", "init", role, "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)


# Importing --------------------------------------------------------------


def test_import_requires_a_recipient(repo: config.SecretsRepo, tmp_path: Path):
    result = _import(repo.path, "orphan", "x", tmp_path)
    assert result.exit_code == 1
    assert "--host or --role" in _out(result)


def test_import_refuses_unconfigured_role(repo: config.SecretsRepo, tmp_path: Path):
    result = _import(repo.path, "tok", "x", tmp_path, "--role", "nope")
    assert result.exit_code == 1
    assert "role init" in _out(result)


def test_import_role_writes_one_shared_copy(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    _member(repo, "svc", "two")

    result = _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc")
    assert result.exit_code == 0, _out(result)

    # One file, under the role -- not a copy per member.
    assert repo.role_secret_path("svc", "tok").exists()
    for hostname in ("one", "two"):
        assert not (
            repo.host_deploy_path(hostname) / "secrets" / "tok.age").exists()

        entry = host_secrets.load_host_manifest(
            repo.deploy_path, hostname).secrets["tok"]
        assert entry.role == "svc"
        assert entry.source == "../../roles/svc/secrets/tok.age"
        assert entry.target == "/run/svc/tok"


def test_role_member_can_decrypt_via_the_role_key(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """The two-phase path end to end: master key -> role key -> secret."""
    _init_role(repo, "svc")
    keypair = _member(repo, "svc", "one")

    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    host_identity = tmp_path / "host.key"
    host_identity.write_text(keypair.private_key + "\n")

    role_privkey = crypto.decrypt_age(
        repo.host_role_key_path("one", "svc"), identity_path=host_identity)

    role_identity = tmp_path / "role.key"
    role_identity.write_text(role_privkey.strip() + "\n")

    plaintext = crypto.decrypt_age(
        repo.role_secret_path("svc", "tok"), identity_path=role_identity)
    assert plaintext.strip() == "s3cret"


def test_non_member_cannot_decrypt_a_role_secret(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "member")
    outsider = add_host(repo, "outsider")
    assert outsider is not None

    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    identity = tmp_path / "outsider.key"
    identity.write_text(outsider.private_key + "\n")

    try:
        crypto.decrypt_age(
            repo.role_secret_path("svc", "tok"), identity_path=identity)
    except Exception:
        pass
    else:
        raise AssertionError("a non-member decrypted a role secret")


def test_import_role_and_host_together(repo: config.SecretsRepo, tmp_path: Path):
    """Both destinations are honoured, and they are separate files."""
    _init_role(repo, "svc")
    _member(repo, "svc", "member")
    add_host(repo, "solo")

    result = _import(
        repo.path, "tok", "s3cret", tmp_path, "--role", "svc", "--host", "solo")
    assert result.exit_code == 0, _out(result)

    assert repo.role_secret_path("svc", "tok").exists()
    assert (repo.host_deploy_path("solo") / "secrets" / "tok.age").exists()

    solo = host_secrets.load_host_manifest(repo.deploy_path, "solo").secrets["tok"]
    assert solo.role is None
    assert solo.source == "secrets/tok.age"


def test_import_overwrite_requires_force(repo: config.SecretsRepo, tmp_path: Path):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")

    assert _import(repo.path, "tok", "first", tmp_path, "--role", "svc").exit_code == 0
    before = repo.role_secret_path("svc", "tok").read_bytes()

    again = _import(repo.path, "tok", "second", tmp_path, "--role", "svc")
    assert again.exit_code == 1
    assert "already exists" in _out(again)
    assert repo.role_secret_path("svc", "tok").read_bytes() == before

    forced = _import(
        repo.path, "tok", "second", tmp_path, "--role", "svc", "--force")
    assert forced.exit_code == 0, _out(forced)
    assert repo.role_secret_path("svc", "tok").read_bytes() != before


def test_import_legacy_two_positional_form_still_works(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """'aegis secret import HOST NAME' predates --host; scripts still use it."""
    add_host(repo, "oldstyle")

    source = tmp_path / "tok.plain"
    source.write_text("s3cret")
    result = runner.invoke(app, [
        "secret", "import", "oldstyle", "tok",
        "--file", str(source),
        "--target", "/run/svc/tok",
        "--secrets-path", str(repo.path),
    ])

    assert result.exit_code == 0, _out(result)
    assert (repo.host_deploy_path("oldstyle") / "secrets" / "tok.age").exists()
    assert "--host oldstyle" in _out(result)


# Membership -------------------------------------------------------------


def test_placement_is_inherited_by_hosts_joining_later(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """The whole point: the service moves, and nothing has to be restated."""
    _init_role(repo, "svc")
    _member(repo, "svc", "first")

    source = tmp_path / "tok.plain"
    source.write_text("s3cret")
    result = runner.invoke(app, [
        "secret", "import", "tok",
        "--role", "svc",
        "--file", str(source),
        "--target", "/run/svc/token",
        "--user", "svcuser", "--group", "svcuser", "--mode", "0440",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, _out(result)

    ciphertext = repo.role_secret_path("svc", "tok").read_bytes()

    _member(repo, "svc", "later")

    entry = host_secrets.load_host_manifest(
        repo.deploy_path, "later").secrets["tok"]
    assert entry.role == "svc"
    assert entry.target == "/run/svc/token"
    assert entry.user == "svcuser"
    assert entry.mode == "0440"

    # Nothing was re-encrypted: no plaintext was needed to extend access.
    assert repo.role_secret_path("svc", "tok").read_bytes() == ciphertext


def test_remove_host_drops_the_entries_but_keeps_the_secret(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "leaver")
    _member(repo, "svc", "stayer")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    result = runner.invoke(app, [
        "role", "remove-host", "svc", "leaver",
        "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)

    assert "tok" not in host_secrets.load_host_manifest(
        repo.deploy_path, "leaver").secrets
    assert "tok" in host_secrets.load_host_manifest(
        repo.deploy_path, "stayer").secrets
    assert repo.role_secret_path("svc", "tok").exists()

    # Revocation is not rotation, and the operator is told so.
    assert "rotate" in _out(result)


def test_build_role_secrets_repairs_a_hand_edited_manifest(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "one")
    del manifest.secrets["tok"]
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    result = runner.invoke(app, [
        "build", "role-secrets", "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)

    assert "tok" in host_secrets.load_host_manifest(
        repo.deploy_path, "one").secrets


def test_a_host_secret_shadowing_a_role_secret_is_reported(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """Same name from two sources: the manifest has one key, so say so."""
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    assert _import(repo.path, "tok", "role-value", tmp_path, "--role", "svc").exit_code == 0
    assert _import(
        repo.path, "tok", "host-value", tmp_path, "--host", "one").exit_code == 0

    entry = host_secrets.load_host_manifest(repo.deploy_path, "one").secrets["tok"]
    assert entry.role is None, "the host's own copy should win, being more specific"

    report = cli_check.run_check(repo)
    assert "shadowing" in "\n".join(f.message for f in report.findings)


# check ------------------------------------------------------------------


def test_check_is_clean_for_a_well_formed_role_secret(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    report = cli_check.run_check(repo)
    assert report.errors == [], "\n".join(f.message for f in report.errors)


def test_check_flags_a_member_that_does_not_declare_the_secret(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "one")
    del manifest.secrets["tok"]
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    report = cli_check.run_check(repo)
    messages = "\n".join(f.message for f in report.errors)
    assert "does not declare every role secret" in messages


def test_check_warns_when_a_role_secret_has_no_members(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    report = cli_check.run_check(repo)
    assert "no members" in "\n".join(f.message for f in report.warnings)


def test_role_secrets_are_covered_by_the_recipient_policy(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """Not 'legacy': check must know who a role secret is meant to be readable by."""
    from aegis import admin, recipients

    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    path = repo.role_secret_path("svc", "tok")
    policies = {p.path: p for p in recipients.plan(repo, admin.recipients(repo))}

    assert path in policies
    policy = policies[path]
    assert policy.category == recipients.CAT_ROLE
    assert policy.resolvable
    assert repo.role_pubkey_path("svc").read_text().strip() in policy.recipients


# Placement --------------------------------------------------------------


def test_role_set_placement_reaches_every_member(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")
    _member(repo, "svc", "one")
    _member(repo, "svc", "two")
    assert _import(repo.path, "tok", "s3cret", tmp_path, "--role", "svc").exit_code == 0

    result = runner.invoke(app, [
        "role", "set-placement", "svc", "secret:tok",
        "--target", "/etc/svc/token", "--mode", "0600",
        "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)

    for hostname in ("one", "two"):
        entry = host_secrets.load_host_manifest(
            repo.deploy_path, hostname).secrets["tok"]
        assert entry.target == "/etc/svc/token"
        assert entry.mode == "0600"


def test_role_placement_survives_a_config_round_trip(repo: config.SecretsRepo):
    role_config = config.RoleConfig(name="svc", hosts=["one"])
    role_config.set_placement(
        "secret:tok", config.Placement(target="/run/svc/tok", mode="0440"))
    repo.set_role_config(role_config)

    loaded = repo.get_role_config("svc")
    assert loaded is not None
    assert loaded.hosts == ["one"]
    assert loaded.placement_for("secret:tok").target == "/run/svc/tok"
    assert loaded.placement_for("secret:tok").mode == "0440"


def test_rotation_reuses_the_recorded_placement(
    repo: config.SecretsRepo, tmp_path: Path,
):
    """--force is for changing the value, not for restating where it goes."""
    _init_role(repo, "svc")
    _member(repo, "svc", "one")

    first = runner.invoke(app, [
        "secret", "import", "tok", "--role", "svc",
        "--file", str(_written(tmp_path, "tok", "first")),
        "--target", "/etc/svc/token",
        "--user", "svcuser", "--group", "svcuser", "--mode", "0440",
        "--secrets-path", str(repo.path)])
    assert first.exit_code == 0, _out(first)

    second = runner.invoke(app, [
        "secret", "import", "tok", "--role", "svc", "--force",
        "--file", str(_written(tmp_path, "tok", "second")),
        "--secrets-path", str(repo.path)])
    assert second.exit_code == 0, _out(second)

    entry = host_secrets.load_host_manifest(repo.deploy_path, "one").secrets["tok"]
    assert entry.target == "/etc/svc/token"
    assert entry.user == "svcuser"
    assert entry.mode == "0440"


def test_first_import_still_requires_a_target(
    repo: config.SecretsRepo, tmp_path: Path,
):
    _init_role(repo, "svc")

    result = runner.invoke(app, [
        "secret", "import", "tok", "--role", "svc",
        "--file", str(_written(tmp_path, "tok", "s3cret")),
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert "--target is required" in _out(result)
