"""`aegis build user-secrets`, checked the way a host consumes its output.

The host reads manifest.age with its master key, then decrypts
secrets/<key> for every manifest key, also with its master key
(aegis modules/secrets.nix, userSecretsScript).  These tests hold the build
to exactly that contract.
"""

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


@pytest.fixture
def setup(repo: config.SecretsRepo, tmp_path_factory, monkeypatch):
    """One host, one user, and the user's own secrets repo."""
    host = add_host(repo, "lambda")
    key_file = tmp_path_factory.mktemp("host") / "master-key"
    key_file.write_text(host.private_key + "\n")

    result = runner.invoke(app, [
        "user", "add", "alice", "--hosts", "lambda",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, _out(result)
    user_pub = repo.get_user_config("alice").public_key

    user_repo = tmp_path_factory.mktemp("aegis-secrets-alice")
    (user_repo / "env").mkdir()
    (user_repo / "files").mkdir()
    monkeypatch.setenv("AEGIS_USER_REPO_ALICE", str(user_repo))

    def put(kind: str, name: str, content: bytes) -> None:
        crypto.encrypt_age(content, [user_pub], user_repo / kind / f"{name}.age")

    return repo, key_file, user_repo, put


def _build(repo: config.SecretsRepo):
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

    (user_repo / "env" / "DROP.age").unlink()
    result = _build(repo)
    assert result.exit_code == 0, _out(result)
    assert "removed DROP" in _out(result)

    assert _host_view(repo, key_file) == {("KEEP", "env"): b"a"}
    after = {p.name for p in secrets_dir.iterdir()}
    assert len(after) == 1 and after <= before


def test_missing_user_repo_fails_the_build(setup, monkeypatch):
    repo, *_ = setup
    monkeypatch.delenv("AEGIS_USER_REPO_ALICE")
    result = _build(repo)
    assert result.exit_code == 1
    assert "could not find their secrets repo" in _out(result)
    assert "complete!" not in _out(result)


def test_undecryptable_secret_fails_the_build(setup):
    repo, _, user_repo, _ = setup
    stranger = crypto.generate_age_keypair()
    crypto.encrypt_age(b"x", [stranger.public_key], user_repo / "env" / "BAD.age")
    result = _build(repo)
    assert result.exit_code == 1
    assert "could not decrypt env BAD" in _out(result)


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
