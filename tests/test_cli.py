"""Tests for CLI commands."""

import pytest
from pathlib import Path
from typer.testing import CliRunner

from aegis.cli import app
from aegis import config, crypto, host_secrets


runner = CliRunner()


def _out(result):
    """Helper: stdout + stderr joined, for readable failure messages."""
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


@pytest.fixture
def temp_secrets_repo(repo_path: Path) -> Path:
    """A temporary secrets repo with a registered admin key."""
    return repo_path


def test_status_empty_repo(temp_secrets_repo: Path):
    """Status command works on empty repo."""
    result = runner.invoke(app, ["status", "--secrets-path", str(temp_secrets_repo)])

    assert result.exit_code == 0
    assert "Configured hosts: 0" in result.stdout


def test_init_host(temp_secrets_repo: Path):
    """Initialize a host."""
    result = runner.invoke(app, [
        "host", "add", "testhost",
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
    runner.invoke(app, ["host", "add", "testhost", "--secrets-path", str(temp_secrets_repo)])
    result = runner.invoke(app, ["host", "add", "testhost", "--secrets-path", str(temp_secrets_repo)])

    assert result.exit_code == 1
    assert "already configured" in result.stdout


def test_add_user(temp_secrets_repo: Path):
    """Add a user with keypair generation."""
    result = runner.invoke(app, [
        "user", "add", "alice",
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
    result = runner.invoke(app, ["secret", "list", "--secrets-path", str(temp_secrets_repo)])

    assert result.exit_code == 0


def test_list_with_host(temp_secrets_repo: Path):
    """List command with a host."""
    # Initialize a host first
    runner.invoke(app, ["host", "add", "testhost", "--secrets-path", str(temp_secrets_repo)])

    result = runner.invoke(app, ["secret", "list", "testhost", "--secrets-path", str(temp_secrets_repo)])

    assert result.exit_code == 0
    assert "testhost" in result.stdout


# aegis secret new ----------------------------------------------------------
#
# These tests use the conftest fixtures: `repo` (initialized secrets repo with
# an admin key registered), `admin_key` (the matching age keypair), and the
# `add_host` helper that registers a host and returns its generated keypair.


def test_new_secret_requires_recipient(temp_secrets_repo: Path):
    """Refuses when neither --host nor --role is given."""
    result = runner.invoke(app, [
        "secret", "new", "demo",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ])

    assert result.exit_code == 1
    assert "--host or --role" in _out(result)


def test_new_secret_refuses_unknown_host(temp_secrets_repo: Path):
    """Refuses --host that has no src/hosts/<h>.toml."""
    result = runner.invoke(app, [
        "secret", "new", "demo",
        "--host", "ghost",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ])

    assert result.exit_code == 1
    assert "ghost" in _out(result)
    assert "host add" in _out(result)


def test_new_secret_writes_per_host_age(temp_secrets_repo: Path):
    """Encrypts the same plaintext for each named host."""

    # Inject host configs directly (faster than running add-host-to-role,
    # which would also need role init for unrelated cases).
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "h1")
    add_host(repo, "h2")
    add_host(repo, "h3")

    result = runner.invoke(app, [
        "secret", "new", "demo-token",
        "--host", "h1", "--host", "h2", "--host", "h3",
        "--target", "/run/demo/token",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out(result)

    # Per-host .age files exist
    for h in ("h1", "h2", "h3"):
        path = repo.host_deploy_path(h) / "secrets" / "demo-token.age"
        assert path.exists(), f"missing {path}"

    # manifest entries
    from aegis import host_secrets as hs
    for h in ("h1", "h2", "h3"):
        manifest = hs.load_host_manifest(repo.deploy_path, h)
        assert "demo-token" in manifest.secrets
        entry = manifest.secrets["demo-token"]
        assert entry.target == "/run/demo/token"


def test_new_secret_host_overwrite_requires_force(temp_secrets_repo: Path):
    """Re-running without --force refuses; with --force succeeds."""
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "h1")

    args = [
        "secret", "new", "demo",
        "--host", "h1",
        "--target", "/run/x",
        "--force",  # First run gets --force to bypass nothing; verifying
                    # mostly that exit code is 0.
        "--secrets-path", str(temp_secrets_repo),
    ]
    assert runner.invoke(app, args).exit_code == 0, _out(args)

    # Second run without --force
    args2 = [
        "secret", "new", "demo",
        "--host", "h1",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ]
    r2 = runner.invoke(app, args2)
    assert r2.exit_code == 1
    assert "already exists" in _out(r2)

    # Third run with --force succeeds
    args3 = list(args)
    runner.invoke(app, args3)


def test_new_secret_refuses_unconfigured_role(temp_secrets_repo: Path):
    """Refuses --role when no src/roles/<r>.toml exists."""
    result = runner.invoke(app, [
        "secret", "new", "demo",
        "--role", "no-such-role",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 1
    assert "no-such-role" in _out(result)
    assert "role init" in _out(result)


def test_new_secret_role_writes_one_copy_under_the_role(
    temp_secrets_repo: Path,
):
    """A role secret is one file; members reference it, non-members do not."""

    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "m1")
    add_host(repo, "m2")
    # m3 is host-initialised but NOT in the role.
    add_host(repo, "m3")

    # Init the role with empty member set, then add m1 and m2.
    r_init = runner.invoke(app, [
        "role", "init", "shared-role",
        "--secrets-path", str(temp_secrets_repo)])
    assert r_init.exit_code == 0, _out([r_init])

    for h in ("m1", "m2"):
        r = runner.invoke(app, [
            "role", "add-host", "shared-role", h,
            "--secrets-path", str(temp_secrets_repo)])
        assert r.exit_code == 0, _out([r])

    # Per-host role-key files for decrypt at boot.
    r_build = runner.invoke(app, [
        "build", "role-keys", "--secrets-path", str(temp_secrets_repo)])
    assert r_build.exit_code == 0, _out([r_build])

    # Now create the secret.
    result = runner.invoke(app, [
        "secret", "new", "shared-token",
        "--role", "shared-role",
        "--target", "/run/shared/token",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out([result])

    # Exactly one ciphertext, under the role -- not a copy per member.
    assert repo.role_secret_path("shared-role", "shared-token").exists()
    for h in ("m1", "m2", "m3"):
        assert not (repo.host_deploy_path(h) / "secrets" / "shared-token.age").exists()

    # m1 and m2 declare it, pointing at the role's copy; m3 does not.
    for h in ("m1", "m2"):
        manifest = host_secrets.load_host_manifest(repo.deploy_path, h)
        entry = manifest.secrets["shared-token"]
        assert entry.role == "shared-role"
        assert entry.source == "../../roles/shared-role/secrets/shared-token.age"
        assert entry.target == "/run/shared/token"

    m3_manifest = host_secrets.load_host_manifest(repo.deploy_path, "m3")
    assert "shared-token" not in m3_manifest.secrets


def test_role_add_host_grants_existing_role_secrets(temp_secrets_repo: Path):
    """The point of roles: a host joining later gets the secret, no re-import."""

    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "first")
    add_host(repo, "later")

    runner.invoke(app, [
        "role", "init", "svc", "--secrets-path", str(temp_secrets_repo)])
    runner.invoke(app, [
        "role", "add-host", "svc", "first",
        "--secrets-path", str(temp_secrets_repo)])
    r = runner.invoke(app, [
        "secret", "new", "svc-token",
        "--role", "svc",
        "--target", "/run/svc/token",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert r.exit_code == 0, _out([r])

    before = repo.role_secret_path("svc", "svc-token").read_bytes()

    r_add = runner.invoke(app, [
        "role", "add-host", "svc", "later",
        "--secrets-path", str(temp_secrets_repo)])
    assert r_add.exit_code == 0, _out([r_add])

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "later")
    assert manifest.secrets["svc-token"].role == "svc"
    assert manifest.secrets["svc-token"].target == "/run/svc/token"

    # The secret itself was not touched: no re-encryption, no plaintext needed.
    assert repo.role_secret_path("svc", "svc-token").read_bytes() == before


def test_role_remove_host_drops_the_role_secrets(temp_secrets_repo: Path):
    """Leaving the role stops the host deploying what the role holds."""

    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "leaver")

    runner.invoke(app, [
        "role", "init", "svc", "--secrets-path", str(temp_secrets_repo)])
    runner.invoke(app, [
        "role", "add-host", "svc", "leaver",
        "--secrets-path", str(temp_secrets_repo)])
    runner.invoke(app, [
        "secret", "new", "svc-token", "--role", "svc",
        "--target", "/run/svc/token",
        "--secrets-path", str(temp_secrets_repo)])

    assert "svc-token" in host_secrets.load_host_manifest(
        repo.deploy_path, "leaver").secrets

    r = runner.invoke(app, [
        "role", "remove-host", "svc", "leaver",
        "--secrets-path", str(temp_secrets_repo)])
    assert r.exit_code == 0, _out([r])

    assert "svc-token" not in host_secrets.load_host_manifest(
        repo.deploy_path, "leaver").secrets
    # The role keeps the secret for its remaining (and future) members.
    assert repo.role_secret_path("svc", "svc-token").exists()


def test_new_secret_host_and_role_are_both_honoured(
    temp_secrets_repo: Path,
):
    """--host and --role are independent destinations for the same plaintext."""

    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "m1")  # in role
    add_host(repo, "extra")  # direct --host only

    runner.invoke(app, [
        "role", "init", "shared-role",
        "--secrets-path", str(temp_secrets_repo)])
    r1 = runner.invoke(app, [
        "role", "add-host", "shared-role", "m1",
        "--secrets-path", str(temp_secrets_repo)])
    assert r1.exit_code == 0, _out([r1])
    runner.invoke(app, [
        "build", "role-keys", "--secrets-path", str(temp_secrets_repo)])

    # m1 is named directly AND is a member of the role: it gets its own copy
    # from --host, and the role's copy is a separate file.
    result = runner.invoke(app, [
        "secret", "new", "demo",
        "--host", "m1", "--host", "extra",
        "--role", "shared-role",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out([result])

    assert (repo.host_deploy_path("m1") / "secrets" / "demo.age").exists()
    assert (repo.host_deploy_path("extra") / "secrets" / "demo.age").exists()
    assert repo.role_secret_path("shared-role", "demo").exists()

    # And the role should appear in the success summary.
    assert "shared-role" in result.stdout


def test_new_secret_role_with_no_members_succeeds_and_says_so(
    temp_secrets_repo: Path,
):
    """A memberless role is a legitimate destination -- the secret waits there.

    It used to be an error, back when --role meant "expand to today's
    members". Now the role holds the secret and the first host to join
    picks it up, so refusing would forbid declaring a service before the
    machine that runs it exists.
    """
    repo = config.SecretsRepo(temp_secrets_repo)
    runner.invoke(app, [
        "role", "init", "empty-role",
        "--secrets-path", str(temp_secrets_repo)])
    result = runner.invoke(app, [
        "secret", "new", "demo",
        "--role", "empty-role",
        "--target", "/run/x",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out([result])
    assert repo.role_secret_path("empty-role", "demo").exists()
    assert "no members" in _out(result)
    assert "role add-host" in _out(result)


# Wildcard user-host membership -----------------------------------------------
#
# `aegis add-user --hosts='*'` should make the user reachable on every active
# host. Hosts added after the user is configured should be picked up on
# the next build-user-secrets without an explicit `add-user`-equivalent edit.


def test_add_user_wildcard_creates_user_config_with_star(temp_secrets_repo: Path):
    """--hosts='*' produces hosts=['*'] in the user config, no error."""
    result = runner.invoke(app, [
        "add-user", "niten",
        "--hosts", "*",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out([result])

    repo = config.SecretsRepo(temp_secrets_repo)
    user_config = repo.get_user_config("niten")
    assert user_config is not None
    assert user_config.hosts == ["*"]


def test_resolve_user_allowed_hosts_expands_star(temp_secrets_repo: Path):
    """The '*' sentinel expands to every active host at call time."""
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "alpha")
    add_host(repo, "beta")

    result = runner.invoke(app, [
        "add-user", "niten",
        "--hosts", "*",
        "--secrets-path", str(temp_secrets_repo),
    ])
    assert result.exit_code == 0, _out([result])

    user_config = repo.get_user_config("niten")
    allowed = repo.resolve_user_allowed_hosts(user_config)
    # Reserve the right to add more hosts later, but alpha and beta
    # must both be present.
    assert "alpha" in allowed
    assert "beta" in allowed
    assert "*" not in allowed  # the sentinel never leaks into the resolved set


def test_resolve_user_allowed_hosts_mixed_explicit_and_star(temp_secrets_repo: Path):
    """Mixed 'alpha,*' resolves to the union of all active hosts."""
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "alpha")
    add_host(repo, "beta")

    runner.invoke(app, [
        "add-user", "niten",
        "--hosts", "alpha,*",
        "--secrets-path", str(temp_secrets_repo),
    ])
    user_config = repo.get_user_config("niten")
    assert user_config.hosts == ["alpha", "*"]

    allowed = repo.resolve_user_allowed_hosts(user_config)
    assert "alpha" in allowed
    assert "beta" in allowed


def test_resolve_user_allowed_hosts_excludes_retired(temp_secrets_repo: Path):
    """Wildcard does NOT grant access to retired hosts."""
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "active-host")
    add_host(repo, "retired-host")

    # Mark retired-host as retired
    retired_config = repo.get_host_config("retired-host")
    retired_config.status = config.STATUS_RETIRED
    repo.set_host_config(retired_config)

    runner.invoke(app, [
        "add-user", "niten",
        "--hosts", "*",
        "--secrets-path", str(temp_secrets_repo),
    ])
    user_config = repo.get_user_config("niten")
    allowed = repo.resolve_user_allowed_hosts(user_config)

    assert "active-host" in allowed
    assert "retired-host" not in allowed


def test_resolve_user_no_wildcard_is_passthrough(temp_secrets_repo: Path):
    """A user without '*' keeps exactly the hosts they were configured with."""
    from tests.conftest import add_host
    repo = config.SecretsRepo(temp_secrets_repo)
    add_host(repo, "alpha")
    add_host(repo, "beta")
    add_host(repo, "gamma")

    runner.invoke(app, [
        "add-user", "niten",
        "--hosts", "alpha,beta",
        "--secrets-path", str(temp_secrets_repo),
    ])
    user_config = repo.get_user_config("niten")
    allowed = repo.resolve_user_allowed_hosts(user_config)

    assert allowed == {"alpha", "beta"}


