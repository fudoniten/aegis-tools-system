"""Bringing a user's own secrets repo into the system repo.

A user keeps their secrets in a repo of their own (``aegis-user`` writes
``env/<NAME>.age`` and ``files/<name>.age``, encrypted to the user key that
``aegis user add`` generated).  ``aegis user pull`` fetches that repo and
copies the ciphertext into ``src/users/<user>/``, recording the commit it
came from.  ``aegis build user-secrets`` reads only from there, so a build
never depends on where anything is checked out, works offline, and the
system repo's history shows exactly what was deployed and when.

Everything in a user repo is untrusted input: anyone who can push to it can
put files there.  Nothing is copied unless every file passes
:func:`validate`, and a user's pulled copy is replaced as a whole or not at
all.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from . import config, crypto
from .errors import AegisError

# Sub-directory of a user repo -> the secret type the manifest records.
KINDS = {"env": "env", "files": "file"}

# Names become file names on every host the user reaches, so nothing that can
# climb out of a directory, hide, or surprise a shell.  Env names must also be
# usable as environment variable names.
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

DEFAULT_MAX_BYTES = 1024 * 1024


class UserRepoError(AegisError):
    """A user repo could not be fetched, or failed validation."""


@dataclass
class PulledSecrets:
    """The validated ciphertext of one user repo, keyed by (kind dir, name)."""
    files: dict[tuple[str, str], bytes]
    commit: Optional[str]


@dataclass
class PullDiff:
    added: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.added or self.changed or self.removed)


def env_override(username: str) -> Optional[Path]:
    """``AEGIS_USER_REPO_<USER>``: a local checkout to pull from instead.

    For trying changes before they are pushed.  Dashes in the username become
    underscores, since a variable name cannot hold them.
    """
    var = "AEGIS_USER_REPO_" + re.sub(r"[^A-Za-z0-9]", "_", username).upper()
    value = os.environ.get(var)
    return Path(value) if value else None


def _git(*args: str, cwd: Optional[Path] = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise UserRepoError(
            f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def _local_commit(path: Path) -> Optional[str]:
    """HEAD of a local checkout, or None if it is not a git repo."""
    if not (path / ".git").exists():
        return None
    try:
        return _git("rev-parse", "HEAD", cwd=path)
    except UserRepoError:
        return None


@contextmanager
def checkout(url: str, ref: Optional[str] = None) -> Iterator[tuple[Path, str]]:
    """A shallow clone of ``url`` at ``ref`` (default branch if None).

    Yields ``(path, commit)``; the clone is deleted afterwards.  Uses the
    operator's own git credentials, so a private repo works wherever they
    can already clone it.
    """
    with tempfile.TemporaryDirectory(prefix="aegis-user-pull-") as tmp:
        dest = Path(tmp) / "repo"
        args = ["clone", "--quiet", "--depth", "1"]
        if ref:
            args += ["--branch", ref]
        _git(*args, url, str(dest))
        yield dest, _git("rev-parse", "HEAD", cwd=dest)


def validate(
    source: Path,
    username: str,
    user_identity: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[tuple[str, str], bytes]:
    """Read and check every secret in a user repo checkout.

    Raises :class:`UserRepoError` listing every problem found, so one pull
    reports all of them rather than one per attempt.  Checked:

    - names are safe file names, and env names are variable names
    - no symlinks: a link in a clone could point at anything on the admin's
      machine, which would then be encrypted and shipped to hosts
    - no file over ``max_bytes``
    - every file decrypts with the user's key, so a bad file fails here
      rather than in a later build
    """
    found: dict[tuple[str, str], bytes] = {}
    problems: list[str] = []

    for kind_dir in KINDS:
        directory = source / kind_dir
        if directory.is_symlink():
            problems.append(f"{kind_dir}/ is a symlink")
            continue
        if not directory.is_dir():
            continue

        for path in sorted(directory.iterdir()):
            rel = f"{kind_dir}/{path.name}"
            if path.name.startswith(".") and not path.name.endswith(".age"):
                continue  # .gitkeep and the like
            if path.suffix != ".age":
                problems.append(f"{rel}: not an .age file")
                continue
            if path.is_symlink() or not path.is_file():
                problems.append(f"{rel}: not a regular file")
                continue

            name = path.name[: -len(".age")]
            pattern = ENV_NAME_RE if kind_dir == "env" else FILE_NAME_RE
            if not pattern.match(name):
                problems.append(
                    f"{rel}: '{name}' is not a valid "
                    + ("environment variable name" if kind_dir == "env" else "secret name")
                )
                continue

            size = path.stat().st_size
            if size > max_bytes:
                problems.append(f"{rel}: {size} bytes, over the {max_bytes}-byte limit")
                continue

            data = path.read_bytes()
            try:
                crypto.decrypt_age_bytes(path, identity_content=user_identity)
            except Exception:
                problems.append(f"{rel}: does not decrypt with {username}'s key")
                continue

            found[(kind_dir, name)] = data

    if problems:
        raise UserRepoError(
            f"{username}'s repo failed validation; nothing was copied:\n  "
            + "\n  ".join(problems)
        )
    return found


def read_pulled(repo: config.SecretsRepo, username: str) -> dict[tuple[str, str], bytes]:
    """The copy currently in ``src/users/<user>/``."""
    base = repo.user_src_path(username)
    out: dict[tuple[str, str], bytes] = {}
    for kind_dir in KINDS:
        directory = base / kind_dir
        if directory.is_dir():
            for path in sorted(directory.glob("*.age")):
                out[(kind_dir, path.name[: -len(".age")])] = path.read_bytes()
    return out


def diff(old: dict[tuple[str, str], bytes], new: dict[tuple[str, str], bytes]) -> PullDiff:
    label = lambda key: f"{key[0]}/{key[1]}"
    result = PullDiff()
    for key in sorted(new):
        if key not in old:
            result.added.append(label(key))
        elif old[key] != new[key]:
            result.changed.append(label(key))
    result.removed = [label(key) for key in sorted(old) if key not in new]
    return result


def write_pulled(
    repo: config.SecretsRepo,
    username: str,
    secrets: dict[tuple[str, str], bytes],
) -> None:
    """Replace ``src/users/<user>/`` with exactly ``secrets``.

    Written beside the old copy and swapped in, so an interrupted pull
    leaves the previous copy rather than half of each.
    """
    base = repo.user_src_path(username)
    base.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{username}-", dir=base.parent))
    try:
        for kind_dir in KINDS:
            (staging / kind_dir).mkdir()
        for (kind_dir, name), data in secrets.items():
            (staging / kind_dir / f"{name}.age").write_bytes(data)
        if base.exists():
            old = base.with_name(f".{username}.old")
            if old.exists():
                shutil.rmtree(old)
            base.rename(old)
            staging.rename(base)
            shutil.rmtree(old)
        else:
            staging.rename(base)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
