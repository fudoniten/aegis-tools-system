"""`aegis secret move`: re-homing a secret with the admin key.

What matters is that the value arrives intact, the placement goes with it, the
source is gone only once the destination is known good, and every manifest
says the right thing afterwards -- in particular for a host that is both the
source and a member of the destination role, where one name has to change
hands between two entries.
"""

from pathlib import Path

from typer.testing import CliRunner

from aegis import cli_check, config, crypto, host_secrets
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _run(repo: config.SecretsRepo, *args: str):
    return runner.invoke(app, [*args, "--secrets-path", str(repo.path)])


def _ok(repo: config.SecretsRepo, *args: str):
    result = _run(repo, *args)
    assert result.exit_code == 0, _out(result)
    return result


def _import(repo, tmp_path: Path, name: str, value: str, *args: str):
    source = tmp_path / f"{name}.{abs(hash(args))}.plain"
    source.write_text(value)
    return _ok(repo, "secret", "import", name, "--file", str(source), *args)


def _role(repo, role: str, *members: str) -> None:
    _ok(repo, "role", "init", role)
    for member in members:
        if repo.get_host_config(member) is None:
            add_host(repo, member)
        _ok(repo, "role", "add-host", role, member)


def _host_path(repo, host: str, name: str) -> Path:
    return repo.host_deploy_path(host) / "secrets" / f"{name}.age"


def _value(path: Path) -> bytes:
    return crypto.decrypt_age_bytes(path)


def _entry(repo, host: str, name: str):
    return host_secrets.load_host_manifest(repo.deploy_path, host).secrets.get(name)


def _move(repo, name: str, *args: str):
    return _run(repo, "secret", "move", name, *args, "--yes")


# The four directions ------------------------------------------------------

def test_host_to_role_moves_value_placement_and_manifests(repo, tmp_path):
    add_host(repo, "legatus")
    _role(repo, "svc", "tribune")
    _import(repo, tmp_path, "db", "pw\n", "--host", "legatus",
            "--target", "/run/svc/db", "--user", "svc", "--mode", "0440")

    result = _move(repo, "db", "--from-host", "legatus", "--to-role", "svc")
    assert result.exit_code == 0, _out(result)

    assert _value(repo.role_secret_path("svc", "db")) == b"pw\n"
    placement = repo.get_role_config("svc").placement_for("secret:db")
    assert (placement.target, placement.user, placement.mode) == (
        "/run/svc/db", "svc", "0440")

    assert not _host_path(repo, "legatus", "db").exists()
    assert "secret:db" not in repo.get_host_config("legatus").placement
    assert _entry(repo, "legatus", "db") is None

    entry = _entry(repo, "tribune", "db")
    assert entry.role == "svc" and entry.target == "/run/svc/db"
    assert "aegis build" in _out(result)


def test_host_to_role_when_the_source_host_is_a_member(repo, tmp_path):
    """The host's own entry has to give way to the role's, not vanish."""
    _role(repo, "svc", "legatus", "tribune")
    _import(repo, tmp_path, "db", "pw", "--host", "legatus", "--target", "/run/svc/db")

    _ok(repo, "secret", "move", "db", "--from-host", "legatus", "--to-role", "svc", "--yes")

    for host in ("legatus", "tribune"):
        entry = _entry(repo, host, "db")
        assert entry is not None and entry.role == "svc", host
        assert entry.target == "/run/svc/db"
    assert cli_check.run_check(repo).errors == []


def test_role_to_host_when_the_destination_is_a_member(repo, tmp_path):
    """Deleting the role copy must not take the new host entry with it."""
    _role(repo, "svc", "one", "two")
    _import(repo, tmp_path, "tok", "v", "--role", "svc", "--target", "/run/svc/tok")

    result = _move(repo, "tok", "--from-role", "svc", "--to-host", "one")
    assert result.exit_code == 0, _out(result)
    assert "lose this secret" in _out(result) and "two" in _out(result)

    assert _value(_host_path(repo, "one", "tok")) == b"v"
    entry = _entry(repo, "one", "tok")
    assert entry is not None and entry.role is None
    assert entry.target == "/run/svc/tok"
    assert _entry(repo, "two", "tok") is None
    assert not repo.role_secret_path("svc", "tok").exists()
    assert "secret:tok" not in repo.get_role_config("svc").placement


def test_host_to_host(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x/tok")

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b", "--yes")

    assert _value(_host_path(repo, "b", "tok")) == b"v"
    assert _entry(repo, "b", "tok").target == "/run/x/tok"
    assert not _host_path(repo, "a", "tok").exists()
    assert _entry(repo, "a", "tok") is None


def test_role_to_role_with_a_shared_member(repo, tmp_path):
    _role(repo, "old", "one")
    _role(repo, "new", "one")
    _import(repo, tmp_path, "tok", "v", "--role", "old", "--target", "/run/x/tok")

    _ok(repo, "secret", "move", "tok", "--from-role", "old", "--to-role", "new", "--yes")

    entry = _entry(repo, "one", "tok")
    assert entry is not None and entry.role == "new"
    assert not repo.role_secret_path("old", "tok").exists()
    assert _value(repo.role_secret_path("new", "tok")) == b"v"


def test_to_several_destinations_and_rename(repo, tmp_path):
    for h in ("a", "b", "c"):
        add_host(repo, h)
    _role(repo, "svc", "c")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x/tok")

    _ok(repo, "secret", "move", "tok", "--from-host", "a",
        "--to-host", "b", "--to-role", "svc", "--rename", "svc-tok", "--yes")

    assert _value(_host_path(repo, "b", "svc-tok")) == b"v"
    assert _value(repo.role_secret_path("svc", "svc-tok")) == b"v"
    assert _entry(repo, "c", "svc-tok").role == "svc"
    assert not _host_path(repo, "a", "tok").exists()


# Placement ------------------------------------------------------------------

def test_target_override_keeps_owner_and_mode(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/old",
            "--user", "svc", "--group", "svc", "--mode", "0440")

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b",
        "--target", "/run/new", "--yes")

    entry = _entry(repo, "b", "tok")
    assert (entry.target, entry.user, entry.group, entry.mode) == (
        "/run/new", "svc", "svc", "0440")


def test_placement_falls_back_to_the_manifest(repo, tmp_path):
    """Older imports record placement only in the manifest."""
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x/tok",
            "--user", "svc")
    host_cfg = repo.get_host_config("a")
    host_cfg.placement.pop("secret:tok")
    repo.set_host_config(host_cfg)

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b", "--yes")
    entry = _entry(repo, "b", "tok")
    assert (entry.target, entry.user) == ("/run/x/tok", "svc")


def test_stale_destination_placement_is_not_inherited(repo, tmp_path):
    add_host(repo, "a")
    _role(repo, "svc")
    role_cfg = repo.get_role_config("svc")
    role_cfg.set_placement("secret:tok", config.Placement(target="/stale", user="old"))
    repo.set_role_config(role_cfg)
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x/tok")

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-role", "svc", "--yes")
    placement = repo.get_role_config("svc").placement_for("secret:tok")
    assert placement.target == "/run/x/tok" and placement.user is None


# Refusals -------------------------------------------------------------------

def test_existing_destination_needs_force(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "new", "--host", "a", "--target", "/run/x")
    _import(repo, tmp_path, "tok", "old", "--host", "b", "--target", "/run/x")

    result = _move(repo, "tok", "--from-host", "a", "--to-host", "b")
    assert result.exit_code == 1 and "already exists" in _out(result)
    assert _value(_host_path(repo, "b", "tok")) == b"old"

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b",
        "--force", "--yes")
    assert _value(_host_path(repo, "b", "tok")) == b"new"


def test_keep_source_collision_with_a_member_is_refused(repo, tmp_path):
    _role(repo, "svc", "legatus")
    _import(repo, tmp_path, "db", "pw", "--host", "legatus", "--target", "/run/db")

    result = _move(repo, "db", "--from-host", "legatus", "--to-role", "svc",
                   "--keep-source")
    assert result.exit_code == 1, _out(result)
    assert "legatus would get 'db' from host legatus and role svc" in _out(result)
    assert not repo.role_secret_path("svc", "db").exists()

    _ok(repo, "secret", "move", "db", "--from-host", "legatus", "--to-role", "svc",
        "--keep-source", "--force", "--yes")
    assert _host_path(repo, "legatus", "db").exists()
    assert repo.role_secret_path("svc", "db").exists()


def test_keep_source_without_collision(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")

    _ok(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b",
        "--keep-source", "--yes")
    assert _value(_host_path(repo, "a", "tok")) == b"v"
    assert _value(_host_path(repo, "b", "tok")) == b"v"
    assert _entry(repo, "a", "tok") is not None


def test_failure_part_way_leaves_nothing_behind(repo, tmp_path):
    """A destination with no master key is caught before anything is written."""
    add_host(repo, "a")
    add_host(repo, "b")
    repo.set_host_config(config.HostConfig(hostname="nokey"))
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")

    result = _move(repo, "tok", "--from-host", "a", "--to-host", "b", "--to-host", "nokey")
    assert result.exit_code == 1
    assert "No age key configured for nokey" in _out(result)
    assert not _host_path(repo, "b", "tok").exists()
    assert _value(_host_path(repo, "a", "tok")) == b"v"


def test_write_failure_rolls_back_including_a_forced_overwrite(
    repo, tmp_path, monkeypatch,
):
    add_host(repo, "a")
    add_host(repo, "b")
    _role(repo, "svc")
    _import(repo, tmp_path, "tok", "new", "--host", "a", "--target", "/run/x")
    _import(repo, tmp_path, "tok", "old", "--host", "b", "--target", "/run/old")
    manifest_before = (repo.deploy_path / "hosts" / "b" / "secrets.toml").read_text()
    src_before = (repo.src_path / "hosts" / "b.toml").read_text()

    real = crypto.encrypt_age

    def flaky(content, recipients, output_path):
        if "roles" in str(output_path):
            raise RuntimeError("disk on fire")
        return real(content, recipients, output_path)

    monkeypatch.setattr(crypto, "encrypt_age", flaky)

    result = _move(repo, "tok", "--from-host", "a", "--to-host", "b",
                   "--to-role", "svc", "--force")
    assert result.exit_code == 1, _out(result)
    assert "rolled back" in _out(result)

    monkeypatch.setattr(crypto, "encrypt_age", real)
    assert _value(_host_path(repo, "b", "tok")) == b"old"
    assert (repo.deploy_path / "hosts" / "b" / "secrets.toml").read_text() == manifest_before
    assert (repo.src_path / "hosts" / "b.toml").read_text() == src_before
    assert not repo.role_secret_path("svc", "tok").exists()
    assert _value(_host_path(repo, "a", "tok")) == b"new"


def test_dry_run_changes_nothing(repo, tmp_path):
    add_host(repo, "a")
    _role(repo, "svc", "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")
    before = sorted(
        (p, p.read_bytes()) for p in repo.path.rglob("*") if p.is_file())

    result = _run(repo, "secret", "move", "tok", "--from-host", "a",
                  "--to-role", "svc", "--dry-run")
    assert result.exit_code == 0, _out(result)
    assert "[dry-run]" in _out(result)

    after = sorted(
        (p, p.read_bytes()) for p in repo.path.rglob("*") if p.is_file())
    assert before == after


def test_missing_admin_key_is_a_clean_error(repo, tmp_path, monkeypatch):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")
    monkeypatch.setenv("AEGIS_ADMIN_KEY", str(tmp_path / "nope.txt"))

    result = _move(repo, "tok", "--from-host", "a", "--to-host", "b")
    assert result.exit_code == 1
    assert "no admin key at" in _out(result) and "AEGIS_ADMIN_KEY" in _out(result)
    assert "Traceback" not in _out(result)


def test_missing_source_names_the_path(repo):
    add_host(repo, "a")
    _role(repo, "svc")
    result = _move(repo, "nope", "--from-host", "a", "--to-role", "svc")
    assert result.exit_code == 1
    assert "secrets/nope.age" in _out(result)


def test_destination_role_must_exist(repo, tmp_path):
    add_host(repo, "a")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")
    result = _move(repo, "tok", "--from-host", "a", "--to-role", "ghost")
    assert result.exit_code == 1 and "aegis role init ghost" in _out(result)


def test_value_never_printed(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "hunter2-very-secret", "--host", "a", "--target", "/run/x")
    result = _run(repo, "secret", "move", "tok", "--from-host", "a", "--to-host", "b", "--yes")
    assert "hunter2" not in _out(result)


def test_prompts_without_yes(repo, tmp_path):
    add_host(repo, "a")
    add_host(repo, "b")
    _import(repo, tmp_path, "tok", "v", "--host", "a", "--target", "/run/x")
    result = runner.invoke(app, [
        "secret", "move", "tok", "--from-host", "a", "--to-host", "b",
        "--secrets-path", str(repo.path)], input="n\n")
    assert result.exit_code != 0
    assert _host_path(repo, "a", "tok").exists()
    assert not _host_path(repo, "b", "tok").exists()


# secret delete, which move reuses -------------------------------------------

def test_delete_host_copy_lets_the_role_copy_back_in(repo, tmp_path):
    _role(repo, "svc", "one")
    _import(repo, tmp_path, "tok", "role", "--role", "svc", "--target", "/run/x")
    _import(repo, tmp_path, "tok", "host", "--host", "one", "--target", "/run/x")
    assert _entry(repo, "one", "tok").role is None

    _ok(repo, "secret", "delete", "tok", "--host", "one", "--yes")
    assert _entry(repo, "one", "tok").role == "svc"
    assert "secret:tok" not in repo.get_host_config("one").placement


def test_delete_role_copy_spares_a_members_own_copy(repo, tmp_path):
    _role(repo, "svc", "one")
    _import(repo, tmp_path, "tok", "role", "--role", "svc", "--target", "/run/x")
    _import(repo, tmp_path, "tok", "host", "--host", "one", "--target", "/run/x")

    _ok(repo, "secret", "delete", "tok", "--role", "svc", "--yes")
    entry = _entry(repo, "one", "tok")
    assert entry is not None and entry.role is None
    assert "secret:tok" not in repo.get_role_config("svc").placement


def test_delete_everywhere_leaves_no_dangling_entry(repo, tmp_path):
    _role(repo, "svc", "one")
    _import(repo, tmp_path, "tok", "role", "--role", "svc", "--target", "/run/x")
    _import(repo, tmp_path, "tok", "host", "--host", "one", "--target", "/run/x")

    _ok(repo, "secret", "delete", "tok", "--yes")
    assert _entry(repo, "one", "tok") is None


def test_build_after_a_move_keeps_the_deployed_path(repo, tmp_path):
    """NixOS consumers reference the target path, so it must not change."""
    _role(repo, "svc", "tribune")
    add_host(repo, "legatus")
    _import(repo, tmp_path, "db", "pw", "--host", "legatus", "--target", "/run/svc/db")
    before = _entry(repo, "legatus", "db").target

    _ok(repo, "secret", "move", "db", "--from-host", "legatus", "--to-role", "svc", "--yes")
    _ok(repo, "build", "role-secrets")

    entry = _entry(repo, "tribune", "db")
    assert entry.role == "svc" and entry.target == before
    assert host_secrets.manifest_key("db") == "secret-db"
