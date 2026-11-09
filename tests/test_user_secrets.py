"""`aegis build user-secrets`, checked the way a host consumes its output.

The host reads manifest.age with its master key, then decrypts
secrets/<key> for every manifest key, also with its master key
(aegis modules/secrets.nix, userSecretsScript).  These tests hold the build
to exactly that contract.
"""

import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aegis import config, crypto
from aegis import manifest as mf
from aegis.cli import app
from tests.conftest import add_host, requires

runner = CliRunner()

pytestmark = requires("age", "age-keygen")


def _out(result) -> str:
    return (result.stdout or "") + (getattr(result, "stderr", "") or "")


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=path, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def setup(repo: config.SecretsRepo, tmp_path_factory):
    """One host, one user, and the user's own secrets repo (a git repo)."""
    host = add_host(repo, "lambda")
    key_file = tmp_path_factory.mktemp("host") / "master-key"
    key_file.write_text(host.private_key + "\n")

    user_repo = tmp_path_factory.mktemp("alice-remote")
    _git(user_repo, "init", "-q", "-b", "main")
    (user_repo / "env").mkdir()
    (user_repo / "files").mkdir()

    result = runner.invoke(app, [
        "user", "add", "alice", "--hosts", "lambda",
        "--repo-url", user_repo.as_uri(),
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, _out(result)
    user_pub = repo.get_user_config("alice").public_key

    def put(kind: str, name: str, content: bytes) -> None:
        crypto.encrypt_age(content, [user_pub], user_repo / kind / f"{name}.age")
        _git(user_repo, "add", "-A")
        _git(user_repo, "commit", "-q", "-m", f"add {name}")

    return repo, key_file, user_repo, put


def _pull(repo: config.SecretsRepo, *args: str):
    return runner.invoke(app, [
        "user", "pull", *args, "--secrets-path", str(repo.path),
    ])


def _build(repo: config.SecretsRepo, pull: bool = True):
    if pull:
        result = _pull(repo)
        assert result.exit_code == 0, _out(result)
    return runner.invoke(app, [
        "build", "user-secrets", "--secrets-path", str(repo.path),
    ])


def _host_view(repo: config.SecretsRepo, key_file: Path) -> dict[tuple[str, str], bytes]:
    """Decrypt the build output exactly as the host does."""
    user_dir = repo.host_deploy_path("lambda") / "users" / "alice"
    manifest = mf.Manifest.from_yaml(
        crypto.decrypt_age(user_dir / "manifest.age", identity_path=key_file)
    )
    raw = yaml.safe_load(
        crypto.decrypt_age(user_dir / "manifest.age", identity_path=key_file)
    )
    out = {}
    for key, entry in raw["secrets"].items():
        # The host does no renaming: the key IS the file name.
        source = user_dir / "secrets" / key
        assert source.exists(), f"manifest names {key}, which was not written"
        out[(entry["name"], entry["type"])] = crypto._decrypt_with_identity(source, key_file)
    assert len(out) == len(manifest.secrets)
    return out


def test_host_can_decrypt_everything_with_its_master_key(setup):
    repo, key_file, _, put = setup
    blob = bytes(range(256)) + b"\n"
    put("env", "GITHUB_TOKEN", b"tok123")
    put("files", "blob", blob)

    result = _build(repo)
    assert result.exit_code == 0, _out(result)

    assert _host_view(repo, key_file) == {
        ("GITHUB_TOKEN", "env"): b"tok123",
        ("blob", "file"): blob,
    }


def test_removed_secret_is_pruned_and_others_keep_their_names(setup):
    repo, key_file, user_repo, put = setup
    put("env", "KEEP", b"a")
    put("env", "DROP", b"b")
    assert _build(repo).exit_code == 0

    secrets_dir = repo.host_deploy_path("lambda") / "users" / "alice" / "secrets"
    before = {p.name for p in secrets_dir.iterdir()}
    assert len(before) == 2

    _git(user_repo, "rm", "-q", "env/DROP.age")
    _git(user_repo, "commit", "-q", "-m", "drop")
    result = _build(repo)
    assert result.exit_code == 0, _out(result)
    assert "removed DROP" in _out(result)

    assert _host_view(repo, key_file) == {("KEEP", "env"): b"a"}
    after = {p.name for p in secrets_dir.iterdir()}
    assert len(after) == 1 and after <= before


def test_build_without_a_pull_fails(setup):
    repo, *_ = setup
    result = _build(repo, pull=False)
    assert result.exit_code == 1
    assert "nothing pulled yet" in _out(result)
    assert "complete!" not in _out(result)


def test_unreadable_manifest_is_left_alone(setup):
    repo, _, _, put = setup
    put("env", "A", b"a")
    manifest_path = repo.host_deploy_path("lambda") / "users" / "alice" / "manifest.age"
    stranger = crypto.generate_age_keypair()
    crypto.encrypt_age("secrets: {}\n", [stranger.public_key], manifest_path)
    before = manifest_path.read_bytes()

    result = _build(repo)
    assert result.exit_code == 1
    assert "cannot read existing manifest" in _out(result)
    assert manifest_path.read_bytes() == before


def test_new_manifest_keys_are_file_names():
    manifest = mf.Manifest.empty()
    assert manifest.add_or_update("X", "env").endswith(".age")


def test_legacy_manifest_keys_gain_the_suffix():
    legacy = "secrets:\n  ae5753fb2b9f8b48:\n    name: X\n    type: env\n"
    manifest = mf.Manifest.from_yaml(legacy)
    assert list(manifest.secrets) == ["ae5753fb2b9f8b48.age"]
    assert manifest.get_hashed_name("X", "env") == "ae5753fb2b9f8b48.age"


# aegis user pull --------------------------------------------------------------


def test_pull_copies_ciphertext_and_records_commit(setup):
    repo, _, user_repo, put = setup
    put("env", "A", b"a")
    head = _git(user_repo, "rev-parse", "HEAD")

    result = _pull(repo, "alice")
    assert result.exit_code == 0, _out(result)
    assert "+ env/A" in _out(result)
    assert repo.get_user_config("alice").pulled_commit == head
    assert (repo.user_src_path("alice") / "env" / "A.age").read_bytes() == \
        (user_repo / "env" / "A.age").read_bytes()

    # Nothing new: says so, and the build still reads only the pulled copy.
    again = _pull(repo, "alice")
    assert "No changes (1 secrets)" in _out(again)


def test_pull_reports_changes_and_removals(setup):
    repo, _, user_repo, put = setup
    put("env", "A", b"a")
    put("env", "B", b"b")
    assert _pull(repo).exit_code == 0

    put("env", "A", b"a2")
    _git(user_repo, "rm", "-q", "env/B.age")
    _git(user_repo, "commit", "-q", "-m", "drop B")
    put("files", "c", b"c")

    out = _out(_pull(repo))
    assert "~ env/A" in out and "- env/B" in out and "+ files/c" in out
    assert not (repo.user_src_path("alice") / "env" / "B.age").exists()


def test_pull_takes_the_configured_ref(setup):
    repo, _, user_repo, put = setup
    put("env", "MAIN", b"m")
    _git(user_repo, "checkout", "-q", "-b", "deploy")
    put("env", "DEPLOY", b"d")
    _git(user_repo, "checkout", "-q", "main")

    result = runner.invoke(app, [
        "user", "set-repo", "alice", user_repo.as_uri(), "--ref", "deploy",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, _out(result)
    assert _pull(repo).exit_code == 0
    assert (repo.user_src_path("alice") / "env" / "DEPLOY.age").exists()


@pytest.mark.parametrize("kind, name, why", [
    ("env", "not-a-var", "not a valid environment variable name"),
    ("env", "1ST", "not a valid environment variable name"),
    ("files", "-rf", "not a valid secret name"),
])
def test_pull_rejects_unsafe_names(setup, kind, name, why):
    repo, _, _, put = setup
    put(kind, name, b"x")
    result = _pull(repo)
    assert result.exit_code == 1
    assert why in _out(result)
    assert not repo.user_src_path("alice").exists()


def test_pull_rejects_symlinks(setup, tmp_path):
    repo, _, user_repo, put = setup
    put("env", "OK", b"ok")
    outside = tmp_path / "admin-file.age"
    outside.write_text("not for hosts")
    (user_repo / "files" / "leak.age").symlink_to(outside)
    _git(user_repo, "add", "-A")
    _git(user_repo, "commit", "-q", "-m", "link")

    result = _pull(repo)
    assert result.exit_code == 1
    assert "files/leak.age: not a regular file" in _out(result)


def test_pull_rejects_oversized_and_undecryptable_files(setup):
    repo, _, user_repo, put = setup
    put("files", "big", b"x" * 4096)
    stranger = crypto.generate_age_keypair()
    crypto.encrypt_age(b"x", [stranger.public_key], user_repo / "env" / "BAD.age")
    _git(user_repo, "add", "-A")
    _git(user_repo, "commit", "-q", "-m", "bad")

    result = _pull(repo, "--max-bytes", "1024")
    out = _out(result)
    assert result.exit_code == 1
    # Every problem in one pass, not one per attempt.
    assert "files/big.age" in out and "over the 1024-byte limit" in out
    assert "env/BAD.age: does not decrypt with alice's key" in out


def test_failed_pull_keeps_the_previous_copy(setup):
    repo, _, user_repo, put = setup
    put("env", "GOOD", b"g")
    assert _pull(repo).exit_code == 0
    before = repo.get_user_config("alice").pulled_commit

    put("env", "bad-name", b"x")
    assert _pull(repo).exit_code == 1

    assert (repo.user_src_path("alice") / "env" / "GOOD.age").exists()
    assert not (repo.user_src_path("alice") / "env" / "bad-name.age").exists()
    assert repo.get_user_config("alice").pulled_commit == before


def test_pull_from_local_checkout(setup, tmp_path):
    repo, _, _, _ = setup
    local = tmp_path / "work"
    (local / "env").mkdir(parents=True)
    pub = repo.get_user_config("alice").public_key
    crypto.encrypt_age(b"w", [pub], local / "env" / "WIP.age")

    result = _pull(repo, "alice", "--source", str(local))
    assert result.exit_code == 0, _out(result)
    assert (repo.user_src_path("alice") / "env" / "WIP.age").exists()
    # Not a git checkout, so there is no commit to record.
    assert repo.get_user_config("alice").pulled_commit is None


def test_pull_from_env_override(setup, tmp_path, monkeypatch):
    repo, _, user_repo, put = setup
    put("env", "A", b"a")
    monkeypatch.setenv("AEGIS_USER_REPO_ALICE", str(user_repo))
    result = _pull(repo)
    assert result.exit_code == 0, _out(result)
    assert "(local)" in _out(result)


def test_user_without_repo_is_not_pulled(repo: config.SecretsRepo):
    add_host(repo, "lambda")
    runner.invoke(app, ["user", "add", "bob", "--hosts", "lambda",
                        "--secrets-path", str(repo.path)])
    result = _pull(repo)
    assert result.exit_code == 0
    assert "No users have a repo set" in _out(result)

    named = _pull(repo, "bob")
    assert named.exit_code == 1
    assert "set-repo bob" in _out(named)


def test_user_delete_removes_the_pulled_copy(setup):
    repo, _, _, put = setup
    put("env", "A", b"a")
    assert _pull(repo).exit_code == 0
    result = runner.invoke(app, ["user", "delete", "alice", "--yes",
                                 "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)
    assert not repo.user_src_path("alice").exists()
