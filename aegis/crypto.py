"""Cryptographic operations using age."""

import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


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
    """Encrypt content with age for multiple recipients.
    
    Args:
        content: The content to encrypt (str or bytes)
        recipients: List of age public keys
        output_path: Where to write the encrypted file
    """
    if not recipients:
        raise ValueError("At least one recipient is required")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = ["age", "--encrypt", "--armor"]
    for recipient in recipients:
        cmd.extend(["--recipient", recipient])
    cmd.extend(["--output", str(output_path)])
    
    if isinstance(content, bytes):
        # Binary mode - pipe bytes directly
        subprocess.run(cmd, input=content, check=True)
    else:
        # Text mode
        subprocess.run(cmd, input=content, text=True, check=True)


def encrypt_age_binary(
    content: bytes,
    recipients: list[str],
    output_path: Path,
) -> None:
    """Encrypt binary content with age, base64-encoding it first.
    
    Use this for binary data (like Kerberos keys) that needs to be
    stored in age-encrypted files. The content is base64-encoded
    before encryption so it survives text-based handling.
    
    Args:
        content: Binary content to encrypt
        recipients: List of age public keys
        output_path: Where to write the encrypted file
    """
    import base64
    encoded = base64.b64encode(content).decode("ascii")
    # Add a marker so we know it's base64-encoded
    marked = f"base64:{encoded}"
    encrypt_age(marked, recipients, output_path)


def decrypt_age_binary(
    input_path: Path,
    identity_path: Path | None = None,
    identity_content: str | None = None,
) -> bytes:
    """Decrypt an age-encrypted file that was encrypted with encrypt_age_binary.
    
    This handles the base64: prefix marker automatically.
    
    Args:
        input_path: Path to the encrypted file
        identity_path: Path to the identity (private key) file
        identity_content: Or provide the identity content directly
        
    Returns:
        Decrypted content as bytes
    """
    import base64
    content = decrypt_age(input_path, identity_path, identity_content)
    if content.startswith("base64:"):
        return base64.b64decode(content[7:])
    else:
        # Fallback: treat as raw text encoded to bytes
        return content.encode("utf-8")


def decrypt_age(
    input_path: Path,
    identity_path: Path | None = None,
    identity_content: str | None = None,
) -> str:
    """Decrypt an age-encrypted file.
    
    Args:
        input_path: Path to the encrypted file
        identity_path: Path to the identity (private key) file
        identity_content: Or provide the identity content directly
        
    Returns:
        Decrypted content as string
    """
    if identity_path is None and identity_content is None:
        # Try default location
        identity_path = Path.home() / ".config" / "aegis" / "key.txt"
        if not identity_path.exists():
            raise FileNotFoundError(
                f"No identity provided and default not found at {identity_path}"
            )
    
    if identity_content is not None:
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write(identity_content)
            temp_identity = Path(f.name)
        try:
            return _decrypt_with_identity(input_path, temp_identity)
        finally:
            temp_identity.unlink()
    else:
        assert identity_path is not None  # Already checked above
        return _decrypt_with_identity(input_path, identity_path)


def _decrypt_with_identity(input_path: Path, identity_path: Path) -> str:
    """Internal: decrypt with a given identity file."""
    result = subprocess.run(
        ["age", "--decrypt", "--identity", str(identity_path), str(input_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def get_admin_public_key(key_path: Path | None = None) -> str:
    """Get the admin's age public key.
    
    Args:
        key_path: Path to admin's private key (default: ~/.config/aegis/key.txt)
        
    Returns:
        The public key string
    """
    if key_path is None:
        key_path = Path.home() / ".config" / "aegis" / "key.txt"
    
    if not key_path.exists():
        raise FileNotFoundError(
            f"Admin key not found at {key_path}. "
            f"Generate with: age-keygen -o {key_path}"
        )
    
    result = subprocess.run(
        ["age-keygen", "-y", str(key_path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def can_decrypt(encrypted_path: Path, identity_path: Path) -> bool:
    """Check if an identity can decrypt a file.
    
    Returns True if decryption succeeds, False otherwise.
    """
    try:
        decrypt_age(encrypted_path, identity_path=identity_path)
        return True
    except subprocess.CalledProcessError:
        return False
