"""Cryptographic operations using age.

All encryption and decryption here is **binary clean**: content is handed to
``age`` as bytes and read back as bytes.  Callers that want text use
:func:`decrypt_age`, which is a thin UTF-8 decode over :func:`decrypt_age_bytes`.

Historical note: an earlier version base64-encoded binary payloads and prefixed
them with a literal ``base64:`` sentinel, because ``decrypt_age`` ran the
subprocess in text mode and could not carry non-UTF-8 bytes.  That sentinel is
no longer written.  It is still *recognised* on read
(:func:`_unwrap_legacy_base64`) so that material encrypted by the old tools —
notably the Kerberos realm keys and principals already in aegis-secrets —
keeps working without a migration.
"""

import base64
import os
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass

from .errors import AdminKeyError

#: Sentinel written by the pre-binary-clean tooling.  Read-only compatibility.
LEGACY_B64_PREFIX = b"base64:"


@dataclass
class AgeKeypair:
    """An age keypair."""
    private_key: str
    public_key: str


def generate_age_keypair() -> AgeKeypair:
    """Generate a new age keypair."""
    result = subprocess.run(
        ["age-keygen"],
        capture_output=True,
        text=True,
        check=True,
    )

    private_key = result.stdout.strip()

    # Extract public key
    result = subprocess.run(
        ["age-keygen", "-y"],
        input=private_key,
        capture_output=True,
        text=True,
        check=True,
    )
    public_key = result.stdout.strip()

    return AgeKeypair(private_key=private_key, public_key=public_key)


def ssh_pubkey_to_age(ssh_pubkey: str) -> str:
    """Convert an SSH public key to an age public key."""
    result = subprocess.run(
        ["ssh-to-age"],
        input=ssh_pubkey,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def encrypt_age(
    content: str | bytes,
    recipients: list[str],
    output_path: Path,
) -> None:
    """Encrypt content with age for one or more recipients.

    Binary clean: ``bytes`` are written through unchanged, ``str`` is encoded
    as UTF-8 first.  No wrapping or encoding of any kind is applied.

    Args:
        content: The content to encrypt
        recipients: age public keys; must be non-empty and free of duplicates
        output_path: Where to write the encrypted file
    """
    if not recipients:
        raise ValueError("At least one recipient is required")

    # De-duplicate while preserving order; a repeated recipient is harmless to
    # age but makes recipient-set comparisons in `aegis check` noisy.
    seen: set[str] = set()
    unique_recipients = []
    for recipient in recipients:
        if recipient and recipient not in seen:
            seen.add(recipient)
            unique_recipients.append(recipient)

    payload = content.encode("utf-8") if isinstance(content, str) else content

    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["age", "--encrypt", "--armor"]
    for recipient in unique_recipients:
        cmd.extend(["--recipient", recipient])
    cmd.extend(["--output", str(output_path)])

    subprocess.run(cmd, input=payload, check=True, capture_output=True)


def _unwrap_legacy_base64(data: bytes) -> bytes:
    """Strip and decode the legacy ``base64:`` sentinel, if present.

    Files written by the current tooling never carry it, so this is a no-op
    for anything encrypted after the binary-clean migration.
    """
    if data.startswith(LEGACY_B64_PREFIX):
        return base64.b64decode(data[len(LEGACY_B64_PREFIX):])
    return data


def decrypt_age_bytes(
    input_path: Path,
    identity_path: Path | None = None,
    identity_content: str | None = None,
) -> bytes:
    """Decrypt an age-encrypted file, returning raw bytes.

    Args:
        input_path: Path to the encrypted file
        identity_path: Path to the identity (private key) file
        identity_content: Or provide the identity content directly

    Returns:
        Decrypted content as bytes, with any legacy ``base64:`` wrapper removed
    """
    if identity_path is None and identity_content is None:
        identity_path = default_admin_key_path()
        if not identity_path.exists():
            raise FileNotFoundError(
                f"No identity provided and default not found at {identity_path}"
            )

    if identity_content is not None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write(identity_content)
            temp_identity = Path(f.name)
        try:
            raw = _decrypt_with_identity(input_path, temp_identity)
        finally:
            temp_identity.unlink()
    else:
        assert identity_path is not None  # Already checked above
        raw = _decrypt_with_identity(input_path, identity_path)

    return _unwrap_legacy_base64(raw)


def decrypt_age(
    input_path: Path,
    identity_path: Path | None = None,
    identity_content: str | None = None,
) -> str:
    """Decrypt an age-encrypted file, returning text.

    Raises UnicodeDecodeError if the payload is not valid UTF-8; use
    :func:`decrypt_age_bytes` for binary material such as Kerberos keys.
    """
    return decrypt_age_bytes(input_path, identity_path, identity_content).decode("utf-8")


def _decrypt_with_identity(input_path: Path, identity_path: Path) -> bytes:
    """Internal: decrypt with a given identity file, returning raw bytes."""
    result = subprocess.run(
        ["age", "--decrypt", "--identity", str(identity_path), str(input_path)],
        capture_output=True,
        check=True,
    )
    return result.stdout


# Deprecated aliases -------------------------------------------------------
#
# encrypt_age is binary clean now, so these exist only so that any out-of-tree
# caller keeps working.  New code should use encrypt_age/decrypt_age_bytes.

def encrypt_age_binary(
    content: bytes,
    recipients: list[str],
    output_path: Path,
) -> None:
    """Deprecated: use :func:`encrypt_age`, which is binary clean."""
    encrypt_age(content, recipients, output_path)


def decrypt_age_binary(
    input_path: Path,
    identity_path: Path | None = None,
    identity_content: str | None = None,
) -> bytes:
    """Deprecated: use :func:`decrypt_age_bytes`."""
    return decrypt_age_bytes(input_path, identity_path, identity_content)


# Admin key ----------------------------------------------------------------

def default_admin_key_path() -> Path:
    """Path to the admin's own age private key.

    ``AEGIS_ADMIN_KEY`` overrides the default location, so an admin holding
    the key somewhere else — a removable volume, a second identity for a
    different repo — does not have to move it into place.
    """
    override = os.environ.get("AEGIS_ADMIN_KEY")
    if override:
        return Path(override)
    return Path.home() / ".config" / "aegis" / "key.txt"


def public_key_for_identity(key_path: Path) -> str:
    """Derive the age public key for a private key file."""
    result = subprocess.run(
        ["age-keygen", "-y", str(key_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def get_admin_public_key(key_path: Path | None = None) -> str:
    """Get the public key of the admin key held on *this* machine.

    Note this is the local operator's key, which is not necessarily the whole
    recipient set — see :mod:`aegis.admin`.  Prefer
    :func:`aegis.admin.recipients` when choosing who to encrypt for.
    """
    if key_path is None:
        key_path = default_admin_key_path()

    if not key_path.exists():
        raise AdminKeyError(
            f"Admin key not found at {key_path}. "
            f"Generate with: age-keygen -o {key_path}"
        )

    return public_key_for_identity(key_path)


def can_decrypt(encrypted_path: Path, identity_path: Path) -> bool:
    """Check if an identity can decrypt a file.

    Returns True if decryption succeeds, False otherwise.
    """
    try:
        decrypt_age_bytes(encrypted_path, identity_path=identity_path)
        return True
    except subprocess.CalledProcessError:
        return False


def recipients_of(encrypted_path: Path) -> int:
    """Count the age recipient stanzas in an armored file.

    age does not expose *which* keys a file was encrypted to, but the number of
    ``-> X25519`` stanzas in the header is visible and is enough for `aegis
    check` to spot a file that is missing a recipient it should have.
    """
    try:
        with open(encrypted_path, "rb") as f:
            raw = f.read()
    except OSError:
        return 0

    # Armored payload is base64 of the raw age file; decode enough to read the
    # header rather than parsing the armor strictly.
    body = b"".join(
        line for line in raw.splitlines() if not line.startswith(b"-----")
    )
    try:
        decoded = base64.b64decode(body, validate=False)
    except Exception:
        return 0

    return decoded.count(b"-> X25519")
