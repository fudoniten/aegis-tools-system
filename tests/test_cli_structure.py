"""Tests for the shape of the command tree, not what the commands do.

``aegis --help`` is the only map most operators ever read, so the grouping is
a feature: it has to stay a short list of groups, and every pre-grouping name
has to keep working while the tool is in beta.
"""

from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from aegis.cli import LEGACY_COMMANDS, app


runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _resolve(path: list[str]):
    """Walk the command tree, e.g. ['build', 'ssh-keys'].

    Duck-typed rather than isinstance-checked: typer has vendored click in
    some versions, so 'click.Group' is not one stable class.
    """
    command = get_command(app)
    for name in path:
        children = getattr(command, "commands", None)
        if not children or name not in children:
            return None
        command = children[name]
    return command


@pytest.mark.parametrize("old,new", sorted(LEGACY_COMMANDS.items()))
def test_legacy_alias_points_at_a_real_command(old: str, new: list[str]):
    """Every alias resolves; a typo here silently breaks an old invocation."""
    assert _resolve(new) is not None, f"{old} -> {' '.join(new)}"


@pytest.mark.parametrize("old", sorted(LEGACY_COMMANDS))
def test_legacy_name_is_not_also_a_top_level_command(old: str):
    """Aliases are handled by AegisGroup, so they must not be registered."""
    assert old not in get_command(app).commands


def test_legacy_name_still_runs_and_says_where_it_went(repo_path: Path):
    result = runner.invoke(
        app, ["init-host", "testhost", "--secrets-path", str(repo_path)])

    assert result.exit_code == 0
    assert "aegis host add" in _out(result)
    assert (repo_path / "src" / "hosts" / "testhost.toml").exists()


def test_legacy_name_forwards_its_options(repo_path: Path):
    """The rewrite replaces the command name only, not what follows it."""
    result = runner.invoke(
        app, ["list", "--secrets-path", str(repo_path)])

    assert result.exit_code == 0


def test_top_level_help_lists_groups_not_every_command(repo_path: Path):
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    out = _out(result)
    for group in ("build", "host", "user", "role", "secret",
                  "ssh", "nexus", "dnssec", "realm", "admin"):
        assert group in out
    # The flat names are gone from the menu even though they still work.
    assert "build-ssh-host-keys" not in out
    assert "remove-host-from-role" not in out


def test_bare_build_runs_the_full_build(repo_path: Path):
    """'aegis build' must build, not print help, now that build is a group."""
    result = runner.invoke(
        app, ["build", "--dry-run", "--secrets-path", str(repo_path)])

    assert result.exit_code == 0
    assert "Running full build" in _out(result)


def test_build_all_matches_bare_build(repo_path: Path):
    result = runner.invoke(
        app, ["build", "all", "--dry-run", "--secrets-path", str(repo_path)])

    assert result.exit_code == 0
    assert "Running full build" in _out(result)


def test_build_subcommand_runs_one_step(repo_path: Path):
    result = runner.invoke(
        app, ["build", "role-keys", "--dry-run", "--secrets-path", str(repo_path)])

    assert result.exit_code == 0
    assert "Running full build" not in _out(result)


def _every_command():
    """(path, command) for every command in the tree, groups included."""
    found = []

    def walk(cmd, path):
        if path:
            found.append((" ".join(path), cmd))
        for name, sub in getattr(cmd, "commands", {}).items():
            walk(sub, path + [name])

    walk(get_command(app), [])
    return found


@pytest.mark.parametrize("path,command", _every_command(), ids=lambda x: x if isinstance(x, str) else "")
def test_short_help_is_one_scannable_line(path: str, command):
    """Help listings are one line per command, so summaries must stay short.

    A docstring that runs its summary into the next paragraph -- an example
    block with no blank line before it, say -- silently drags that whole
    block into the parent's menu, which is what this grouping was for.
    """
    short = command.get_short_help_str(limit=200)

    assert short, f"{path} has no summary"
    assert "Example" not in short, f"{path} leaks its examples into the menu"
    assert len(short) <= 80, f"{path} summary is {len(short)} chars: {short}"


def test_unknown_command_still_fails(repo_path: Path):
    result = runner.invoke(app, ["definitely-not-a-command"])

    assert result.exit_code != 0


def test_top_level_help_documents_the_environment_variables():
    """Every variable aegis reads, in the place an operator will look.

    A path resolved from the environment is invisible otherwise: the failure
    it produces is "wrong repo", not "unset variable".
    """
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    out = _out(result)
    for variable in (
        "AEGIS_SYSTEM", "AEGIS_ADMIN_KEY", "AEGIS_SCRIPTS", "AEGIS_USER_REPO_",
    ):
        assert variable in out, f"{variable} is not mentioned in 'aegis --help'"


def test_role_commands_are_registered():
    for path in (
        ["role", "init"],
        ["role", "add-host"],
        ["role", "remove-host"],
        ["role", "set-placement"],
        ["build", "role-secrets"],
    ):
        assert _resolve(path) is not None, " ".join(path)


@pytest.mark.parametrize("path", [["secret", "import"], ["secret", "new"]])
def test_documented_defaults_survive_rich_markup(path: list[str]):
    """Rich reads square brackets as markup and silently drops them.

    A help string reading "[default: root]" renders as "" -- the one thing it
    was there to say. Parentheses are not markup.
    """
    command = _resolve(path)
    assert command is not None

    for param in command.params:
        help_text = getattr(param, "help", None) or ""
        assert "[default:" not in help_text, f"{path}/{param.name}: {help_text}"


def test_epilog_survives_every_typer_version():
    """The epilog's layout must not depend on single linebreaks.

    Typer renders it through Rich, and versions before 0.27 collapse every
    single newline in the epilog into a space -- unconditionally, and without
    honouring the \\b marker that works in help text. A column of commands
    written as one paragraph therefore renders as a wall of prose on exactly
    the versions we do not control.

    Blank-line-separated paragraphs are the one structure both versions keep,
    so every line whose layout matters is its own paragraph, and no paragraph
    wraps in the source.
    """
    epilog = get_command(app).epilog or ""
    assert epilog, "the top-level epilog is what this guards"

    assert "\b" not in epilog, (
        "\\b is not honoured in an epilog on any typer version; it is a "
        "literal control character there"
    )

    for paragraph in epilog.split("\n\n"):
        assert "\n" not in paragraph.strip(), (
            f"paragraph spans several lines, so it renders differently per "
            f"typer version:\n{paragraph}"
        )
