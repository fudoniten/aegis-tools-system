"""The reference printed after a secret is created.

The `secret-` prefix is the module's, not the operator's, and a `targets`
lookup without it misses silently -- the service gets nothing while Aegis goes
on decrypting the secret perfectly well. These assert that the tools say so at
the point the secret is made.
"""

from pathlib import Path

from typer.testing import CliRunner

from aegis import config, host_secrets
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def test_manifest_key_and_unit_carry_the_prefix():
    assert host_secrets.manifest_key("adguard.passwd") == "secret-adguard.passwd"
    assert host_secrets.decrypt_unit("adguard.passwd") == (
        "aegis-secret-adguard.passwd.service")


def test_import_prints_the_lookup_and_the_unit(
    repo: config.SecretsRepo, tmp_path: Path
):
    add_host(repo, "rama")
    plaintext = tmp_path / "token"
    plaintext.write_text("hunter2\n")

    result = runner.invoke(app, [
        "secret", "import", "adguard.passwd",
        "--host", "rama",
        "--file", str(plaintext),
        "--target", "/run/adguard-dns-proxy/admin.passwd",
        "--secrets-path", str(repo.path),
    ])

    assert result.exit_code == 0, result.output
    assert 'targets."secret-adguard.passwd"' in result.output
    assert "/run/adguard-dns-proxy/admin.passwd" in result.output
    assert 'after    = [ "aegis-secret-adguard.passwd.service" ]' in result.output
    assert 'requires = [ "aegis-secret-adguard.passwd.service" ]' in result.output


def test_import_names_the_prefix_as_the_trap(
    repo: config.SecretsRepo, tmp_path: Path
):
    add_host(repo, "rama")
    plaintext = tmp_path / "token"
    plaintext.write_text("x")

    result = runner.invoke(app, [
        "secret", "import", "db-password",
        "--host", "rama",
        "--file", str(plaintext),
        "--target", "/run/db/password",
        "--secrets-path", str(repo.path),
    ])

    assert "The 'secret-' prefix is the module's" in result.output


def test_role_import_mentions_phase_two(repo: config.SecretsRepo, tmp_path: Path):
    """A role secret needs the role key, which is what phase 2 is for."""
    add_host(repo, "nomenclator-0")
    runner.invoke(app, ["role", "init", "dns-burg", "--secrets-path", str(repo.path)])
    runner.invoke(app, [
        "role", "add-host", "dns-burg", "nomenclator-0",
        "--secrets-path", str(repo.path),
    ])

    plaintext = tmp_path / "passwd"
    plaintext.write_text("x")

    result = runner.invoke(app, [
        "secret", "import", "adguard.passwd",
        "--role", "dns-burg",
        "--file", str(plaintext),
        "--target", "/run/adguard-dns-proxy/admin.passwd",
        "--secrets-path", str(repo.path),
    ])

    assert result.exit_code == 0, result.output
    assert 'targets."secret-adguard.passwd"' in result.output
    assert "phase 2" in result.output
    assert "dns-burg" in result.output


def test_new_prints_the_reference_too(repo: config.SecretsRepo):
    add_host(repo, "rama")

    result = runner.invoke(app, [
        "secret", "new", "session-key",
        "--host", "rama",
        "--target", "/run/app/session-key",
        "--secrets-path", str(repo.path),
    ])

    assert result.exit_code == 0, result.output
    assert 'targets."secret-session-key"' in result.output
    assert 'aegis-secret-session-key.service' in result.output
    # The plaintext must still not be printed.
    assert "Plaintext was not written to disk" in result.output


def test_add_says_there_is_no_reference_and_why(
    repo: config.SecretsRepo, tmp_path: Path
):
    """`secret add` records no placement, so there is nothing to reference."""
    add_host(repo, "rama")
    plaintext = tmp_path / "blob"
    plaintext.write_text("x")

    result = runner.invoke(app, [
        "secret", "add", "rama", "orphan", str(plaintext),
        "--secrets-path", str(repo.path),
    ])

    assert result.exit_code == 0, result.output
    assert "nothing deploys this" in result.output
    assert "aegis secret import orphan --host rama" in result.output
    assert "targets." not in result.output
