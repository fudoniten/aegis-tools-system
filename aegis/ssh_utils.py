"""SSH key utilities for import operations."""

import re
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


@dataclass
class SSHKeyPair:
    """SSH key pair with private and public keys."""
    key_type: str  # ed25519, ecdsa, rsa
    private_key: str  # PEM format
    public_key: str  # OpenSSH format


def detect_key_type(private_key_content: str) -> str:
    """Detect SSH key type from private key content.
    
    Args:
        private_key_content: Private key in PEM format
        
    Returns:
        Key type: "ed25519", "ecdsa", or "rsa"
        
    Raises:
        ValueError: If key type cannot be detected
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        key_path = tmpdir / "id_key"
        key_path.write_text(private_key_content)
        key_path.chmod(0o600)
        
        # Use ssh-keygen -l to get key info
        cmd = ["ssh-keygen", "-l", "-f", str(key_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise ValueError(f"Cannot detect key type: {result.stderr}")
        
        # Output format: "256 SHA256:xxx user@host (ED25519)"
        # or "256 SHA256:xxx user@host (ECDSA)"
        # or "3072 SHA256:xxx user@host (RSA)"
        match = re.search(r'\(([A-Z0-9]+)\)', result.stdout)
        if not match:
            raise ValueError(f"Cannot parse key type from: {result.stdout}")
        
        key_type = match.group(1).lower()
        
        # Map variations to canonical names
        if key_type in ["ed25519"]:
            return "ed25519"
        elif key_type in ["ecdsa"]:
            return "ecdsa"
        elif key_type in ["rsa"]:
            return "rsa"
        else:
            raise ValueError(f"Unknown key type: {key_type}")


def derive_public_key(private_key_content: str) -> str:
    """Derive OpenSSH public key from private key.
    
    Args:
        private_key_content: Private key in PEM format
        
    Returns:
        Public key in OpenSSH format
        
    Raises:
        subprocess.CalledProcessError: If ssh-keygen fails
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        priv_key_path = tmpdir / "id_key"
        
        # Write private key
        priv_key_path.write_text(private_key_content)
        priv_key_path.chmod(0o600)
        
        # Use ssh-keygen to derive public key
        cmd = ["ssh-keygen", "-y", "-f", str(priv_key_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        return result.stdout.strip()


def validate_private_key(private_key_content: str) -> tuple[bool, str]:
    """Validate that a private key is properly formatted.
    
    Args:
        private_key_content: Private key content
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Try to parse it with ssh-keygen
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            key_path = tmpdir / "test_key"
            key_path.write_text(private_key_content)
            key_path.chmod(0o600)
            
            # This will fail if key is invalid
            cmd = ["ssh-keygen", "-l", "-f", str(key_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return False, f"Invalid key format: {result.stderr}"
            
            return True, ""
    except Exception as e:
        return False, str(e)


def read_ssh_keypair(key_path: Path, hostname: str) -> SSHKeyPair:
    """Read an SSH private key and auto-detect its type.
    
    Args:
        key_path: Path to private key file
        hostname: Hostname for error messages
        
    Returns:
        SSHKeyPair object
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key is invalid or type cannot be detected
    """
    if not key_path.exists():
        raise FileNotFoundError(f"Private key not found: {key_path}")
    
    # Read private key
    private_key = key_path.read_text()
    
    # Detect key type
    try:
        key_type = detect_key_type(private_key)
    except ValueError as e:
        raise ValueError(f"Cannot detect key type for {hostname}: {e}")
    
    # Validate
    is_valid, error = validate_private_key(private_key)
    if not is_valid:
        raise ValueError(f"Invalid {key_type} private key for {hostname}: {error}")
    
    # Derive public key
    try:
        public_key = derive_public_key(private_key)
    except subprocess.CalledProcessError as e:
        raise ValueError(
            f"Failed to derive public key from {key_type} private key: {e.stderr}"
        )
    
    return SSHKeyPair(
        key_type=key_type,
        private_key=private_key,
        public_key=public_key,
    )


def read_ssh_keypairs(
    hostname: str,
    key_files: list[Path],
) -> list[SSHKeyPair]:
    """Read SSH private keys from a list of files and auto-detect types.
    
    Args:
        hostname: Hostname for error messages
        key_files: List of paths to private key files
        
    Returns:
        List of SSHKeyPair objects
        
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key is invalid
    """
    keypairs = []
    
    for key_path in key_files:
        keypair = read_ssh_keypair(key_path, hostname)
        keypairs.append(keypair)
    
    return keypairs
