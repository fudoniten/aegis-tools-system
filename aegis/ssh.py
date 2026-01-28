"""SSH key generation."""

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SSHKeypair:
    """An SSH keypair."""
    private_key: str
    public_key: str
    key_type: str
    comment: str


@dataclass  
class HostSSHKeys:
    """All SSH keys for a host."""
    host_ed25519: SSHKeypair
    host_ecdsa: SSHKeypair
    deploy_ed25519: SSHKeypair
    initrd_ed25519: SSHKeypair
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "host": {
                "ed25519": {
                    "private": self.host_ed25519.private_key,
                    "public": self.host_ed25519.public_key,
                },
                "ecdsa": {
                    "private": self.host_ecdsa.private_key,
                    "public": self.host_ecdsa.public_key,
                },
            },
            "deploy": {
                "ed25519": {
                    "private": self.deploy_ed25519.private_key,
                    "public": self.deploy_ed25519.public_key,
                },
            },
            "initrd": {
                "ed25519": {
                    "private": self.initrd_ed25519.private_key,
                    "public": self.initrd_ed25519.public_key,
                },
            },
        }


def generate_ssh_keypair(
    key_type: str,
    comment: str,
    bits: int | None = None,
) -> SSHKeypair:
    """Generate an SSH keypair.
    
    Args:
        key_type: Key type (ed25519, ecdsa, rsa)
        comment: Comment for the key
        bits: Key size in bits (for RSA/ECDSA)
        
    Returns:
        SSHKeypair with private and public keys
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "key"
        
        cmd = [
            "ssh-keygen",
            "-t", key_type,
            "-N", "",  # No passphrase
            "-f", str(key_path),
            "-C", comment,
        ]
        
        if bits is not None:
            cmd.extend(["-b", str(bits)])
        
        subprocess.run(cmd, check=True, capture_output=True)
        
        private_key = key_path.read_text()
        public_key = key_path.with_suffix(".pub").read_text().strip()
        
        return SSHKeypair(
            private_key=private_key,
            public_key=public_key,
            key_type=key_type,
            comment=comment,
        )


def generate_host_keys(hostname: str) -> HostSSHKeys:
    """Generate all SSH keys for a host.
    
    Args:
        hostname: The hostname for key comments
        
    Returns:
        HostSSHKeys containing all generated keys
    """
    return HostSSHKeys(
        host_ed25519=generate_ssh_keypair("ed25519", f"host@{hostname}"),
        host_ecdsa=generate_ssh_keypair("ecdsa", f"host-ecdsa@{hostname}"),
        deploy_ed25519=generate_ssh_keypair("ed25519", f"deploy@{hostname}"),
        initrd_ed25519=generate_ssh_keypair("ed25519", f"initrd@{hostname}"),
    )


def generate_sshfp_records(public_keys: list[str], hostname: str) -> list[str]:
    """Generate SSHFP DNS records for public keys.
    
    Args:
        public_keys: List of SSH public key strings
        hostname: Hostname for the records
        
    Returns:
        List of SSHFP record strings
    """
    records = []
    
    with tempfile.TemporaryDirectory() as tmpdir:
        for i, pubkey in enumerate(public_keys):
            pubkey_path = Path(tmpdir) / f"key{i}.pub"
            pubkey_path.write_text(pubkey)
            
            result = subprocess.run(
                ["ssh-keygen", "-r", hostname, "-f", str(pubkey_path)],
                capture_output=True,
                text=True,
                check=True,
            )
            
            for line in result.stdout.strip().split("\n"):
                if line:
                    records.append(line)
    
    return records
