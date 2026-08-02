"""Admin recipient set.

Every secret in the repo is encrypted for the admin in addition to whoever
else needs it, which makes the admin key the recovery path for the entire
system.  A *single* admin key is therefore a single point of total failure:
role private keys, user private keys, Kerberos realm keys and every principal
are encrypted for the admin and nobody else.  Losing it leaves running hosts
untouched but makes it impossible to ever add a host to a realm or a role
again.

So the admin is a *set* of recipients, stored in the repo:

    keys/admin/<name>.pub     one age public key per file

Keeping a second key offline (paper, YubiKey, HSM) turns loss of the everyday
key into a non-event.

``keys/admin.pub`` (a single key at the top level) is the historical layout and
is still read, so existing repos keep working; ``aegis admin migrate`` converts
it to the directory form.
"""

from pathlib import Path

from . import crypto
from .config import SecretsRepo
from .errors import AdminKeyError


def _parse_pubkey_file(path: Path) -> str | None:
    """Read a single age public key from a file, ignoring comments/blanks."""
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                return line
    except OSError:
        return None
    return None


def recipient_files(repo: SecretsRepo) -> list[Path]:
    """List the files making up the admin recipient set, newest layout first."""
    admin_dir = repo.admin_keys_path()
    if admin_dir.is_dir():
        files = sorted(admin_dir.glob("*.pub"))
        if files:
            return files

    legacy = repo.legacy_admin_key_path()
    if legacy.exists():
        return [legacy]

    return []


def recipients(repo: SecretsRepo) -> list[str]:
    """The admin public keys every secret should be encrypted for.

    Raises:
        AdminKeyError: if the repo declares no admin keys at all.
    """
    keys: list[str] = []
    for path in recipient_files(repo):
        key = _parse_pubkey_file(path)
        if key:
            keys.append(key)

    if not keys:
        raise AdminKeyError(
            f"No admin public keys found in {repo.admin_keys_path()} "
            f"or {repo.legacy_admin_key_path()}.\n"
            f"Register yours with: aegis admin add-key --name <name>"
        )

    # Deduplicate, preserve order
    seen: set[str] = set()
    unique = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


def local_public_key() -> str:
    """Public key of the admin identity held on this machine."""
    return crypto.get_admin_public_key()


def validate_local_key(repo: SecretsRepo) -> str:
    """Check that this machine's admin key is part of the repo's recipient set.

    Without this check, using the wrong admin key silently produces files that
    the real admin cannot read — the failure only shows up much later, when
    someone tries to decrypt.

    Returns:
        The local admin public key.

    Raises:
        AdminKeyError: if the local key is not a registered recipient.
    """
    local = local_public_key()
    known = recipients(repo)

    if local not in known:
        raise AdminKeyError(
            f"Local admin key is not registered in this repo.\n"
            f"  local: {local}\n"
            f"  repo:  {', '.join(known)}\n"
            f"\n"
            f"Anything you encrypt would be unreadable by the other admins.\n"
            f"Register it with: aegis admin add-key --name <name>\n"
            f"...or point at the right key with AEGIS_ADMIN_KEY."
        )

    return local


def add_key(repo: SecretsRepo, public_key: str, name: str) -> Path:
    """Register an additional admin public key.

    Note this does not re-encrypt anything: existing secrets remain readable
    only by the keys they were encrypted for.  Run ``aegis reencrypt`` to
    extend the new key's reach to existing material.
    """
    public_key = public_key.strip()
    if not public_key.startswith("age1"):
        raise AdminKeyError(
            f"Not an age public key: {public_key!r} (expected 'age1...')"
        )

    admin_dir = repo.admin_keys_path()
    admin_dir.mkdir(parents=True, exist_ok=True)

    out = admin_dir / f"{name}.pub"
    out.write_text(public_key + "\n")
    return out


def migrate_legacy(repo: SecretsRepo) -> Path | None:
    """Convert a top-level ``keys/admin.pub`` into ``keys/admin/primary.pub``.

    Returns the new path, or None if there was nothing to migrate.
    """
    legacy = repo.legacy_admin_key_path()
    if not legacy.exists():
        return None

    key = _parse_pubkey_file(legacy)
    if not key:
        raise AdminKeyError(f"Could not read an age public key from {legacy}")

    out = add_key(repo, key, "primary")
    legacy.unlink()
    return out
