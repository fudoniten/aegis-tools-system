"""Where 'aegis secret import' gets the plaintext from: --file, --literal, --stdin.

What matters is that each source yields exactly the bytes the operator meant,
with no newline invented or dropped along the way, and that giving none or
several is refused before anything is written.
"""

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from aegis import config, crypto
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _import(repo: config.SecretsRepo, *source: str, input=None):
    return runner.invoke(app, [
        "secret", "import", "tok",
        "--host", "box",
        *source,
        "--target", "/run/svc/tok",
        "--secrets-path", str(repo.path),
    ], input=input)


def _plaintext(repo: config.SecretsRepo, keypair: crypto.AgeKeypair) -> bytes:
    return crypto.decrypt_age_bytes(
        repo.host_deploy_path("box") / "secrets" / "tok.age",
        identity_content=keypair.private_key,
    )


@pytest.fixture
def box(repo: config.SecretsRepo) -> crypto.AgeKeypair:
    keypair = add_host(repo, "box")
    assert keypair is not None
    return keypair


def test_literal_is_stored_exactly_with_no_newline(
    repo: config.SecretsRepo, box: crypto.AgeKeypair,
):
    result = _import(repo, "--literal", "hunter2 with spaces")
    assert result.exit_code == 0, _out(result)
    assert _plaintext(repo, box) == b"hunter2 with spaces"


def test_literal_equals_form(repo: config.SecretsRepo, box: crypto.AgeKeypair):
    result = _import(repo, "--literal=p=ss=word")
    assert result.exit_code == 0, _out(result)
    assert _plaintext(repo, box) == b"p=ss=word"


def test_piped_stdin_is_taken_byte_for_byte(
    repo: config.SecretsRepo, box: crypto.AgeKeypair,
):
    """Same contract as --file: a trailing newline that was piped in stays."""
    result = _import(repo, "--stdin", input="s3cret\n")
    assert result.exit_code == 0, _out(result)
    assert _plaintext(repo, box) == b"s3cret\n"


class _Tty:
    def isatty(self):
        return True


def test_stdin_prompts_without_echo_on_a_terminal(monkeypatch):
    import getpass

    import aegis.cli as cli

    answers = iter(["typed-secret", "typed-secret"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.sys, "stdin", _Tty())

    assert cli._read_secret_from_stdin("tok") == b"typed-secret"


def test_stdin_prompt_mismatch_is_refused(monkeypatch):
    import getpass

    import aegis.cli as cli

    answers = iter(["one", "two"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.sys, "stdin", _Tty())

    with pytest.raises(typer.Exit):
        cli._read_secret_from_stdin("tok")


def test_file_still_works(repo: config.SecretsRepo, box: crypto.AgeKeypair, tmp_path: Path):
    source = tmp_path / "tok.plain"
    source.write_bytes(b"\x00binary\xff")
    result = _import(repo, "--file", str(source))
    assert result.exit_code == 0, _out(result)
    assert _plaintext(repo, box) == b"\x00binary\xff"


@pytest.mark.parametrize("source", [
    [],
    ["--literal", "a", "--stdin"],
    ["--literal", "a", "--file", "/nonexistent"],
])
def test_exactly_one_source_is_required(
    repo: config.SecretsRepo, box: crypto.AgeKeypair, source: list[str],
):
    result = _import(repo, *source, input="x")
    assert result.exit_code == 1
    assert "exactly one of --file, --literal or --stdin" in _out(result)
    assert not (repo.host_deploy_path("box") / "secrets" / "tok.age").exists()


def test_empty_secret_is_refused(repo: config.SecretsRepo, box: crypto.AgeKeypair):
    result = _import(repo, "--literal", "")
    assert result.exit_code == 1
    assert "empty" in _out(result)
    assert not (repo.host_deploy_path("box") / "secrets" / "tok.age").exists()
