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
    """All SSH keys for a host.

    Four keypairs, but only two of them are sshd host keys.  The deploy key is
    for deploy-rs, and the initrd key identifies the initramfs sshd, which is a
    separate server with its own configuration -- neither is an identity the
    running sshd should present.  The distinction is not cosmetic: manifests
    that lost it put all four in ``[[ssh-host-keys]]``, which is exactly where
    ``services.openssh.hostKeys`` is built from.
    """
    host_ed25519: SSHKeypair
    host_ecdsa: SSHKeypair
    deploy_ed25519: SSHKeypair
    initrd_ed25519: SSHKeypair

    def host_key_items(self) -> list[tuple[str, "SSHKeypair"]]:
        """(file_stem, keypair) for the keys sshd presents as this host."""
        return [
            ("ssh_host_ed25519_key", self.host_ed25519),
            ("ssh_host_ecdsa_key", self.host_ecdsa),
        ]

    def auxiliary_items(self) -> list[tuple[str, "SSHKeypair"]]:
        """(file_stem, keypair) for the keys sshd must *not* be handed."""
        return [
            ("deploy_ed25519_key", self.deploy_ed25519),
            ("initrd_ed25519_key", self.initrd_ed25519),
        ]

    def items(self) -> list[tuple[str, "SSHKeypair"]]:
        """Return (file_stem, keypair) pairs for each key.

        The file stem is the intended filename on the SSH server
        (e.g. ssh_host_ed25519_key), without any extension.  Every key is
        encrypted and delivered the same way, so this is the right list for
        writing them out -- but not for building the manifest, which has to
        keep the two categories apart.
        """
        return self.host_key_items() + self.auxiliary_items()


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
