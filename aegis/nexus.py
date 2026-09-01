"""Nexus DDNS key generation utilities."""

import subprocess
from pathlib import Path
from typing import Optional


def generate_key(
    output_path: Path,
    algorithm: str = "HmacSHA512",
    seed: Optional[str] = None,
    verbose: bool = False,
) -> Path:
    """Generate a Nexus DDNS authentication key.
    
    Creates an HMAC key for authenticating Nexus DDNS clients to servers.
    The key is written in the format: ALGORITHM:BASE64_ENCODED_KEY
    
    Args:
        output_path: Path where the key file should be written
        algorithm: HMAC algorithm to use (default: HmacSHA512)
        seed: Optional seed for key generation (for reproducibility)
        verbose: Print verbose output
        
    Returns:
        Path to the created key file
        
    Example:
        >>> key_path = generate_key(Path("./nexus-server.key"))
        >>> # Key file contains: HmacSHA512:dGVzdGtleQ==...
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        "nexus-keygen",
        "--algorithm", algorithm,
    ]
    
    if seed:
        cmd.extend(["--seed", seed])
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.append(str(output_path))
    
    subprocess.run(cmd, check=True)
    
    return output_path


def read_key(key_path: Path) -> tuple[str, str]:
    """Read and parse a Nexus key file.

    Args:
        key_path: Path to the key file

    Returns:
        Tuple of (algorithm, encoded_key)

    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key file format is invalid
    """
    if not key_path.exists():
        raise FileNotFoundError(f"Key file not found: {key_path}")

    content = key_path.read_text().strip()

    try:
        algorithm, encoded_key = content.split(":", 1)
        return algorithm, encoded_key
    except ValueError:
        raise ValueError(f"Invalid key file format: {key_path}")


def generate_keypair(output_path: Path, verbose: bool = False) -> tuple[Path, Path]:
    """Generate a Nexus DDNS Ed25519 keypair for the public-key-authenticated
    /api/v3 API.

    Shells out to `nexus-keygen --keypair`, which writes the private key to
    output_path (owner-only permissions) and the public key to
    output_path + ".pub". Unlike generate_key's HMAC key, only the private
    key is sensitive -- the public key is not secret and needs no encryption
    at rest.

    Args:
        output_path: Path where the private key file should be written
        verbose: Print verbose output

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["nexus-keygen", "--keypair"]

    if verbose:
        cmd.append("--verbose")

    cmd.append(str(output_path))

    subprocess.run(cmd, check=True)

    return output_path, output_path.with_name(output_path.name + ".pub")
