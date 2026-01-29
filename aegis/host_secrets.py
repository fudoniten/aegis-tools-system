"""Host secrets manifest management.

This module manages the secrets.toml manifest file for each host, which
contains metadata about all secrets and their deployment configuration.

The manifest is stored at build/hosts/<hostname>/secrets.toml and can be
imported by NixOS to configure services with the correct paths.

Example manifest:
    
    [ssh-host-keys]
    source = "ssh-host-keys.age"
    target_dir = "/run/aegis/ssh"
    user = "root"
    group = "root"
    mode = "0600"
    key_types = ["ed25519", "ecdsa", "rsa"]
    
    [keytab]
    source = "keytab.age"
    target = "/run/aegis/keytab"
    user = "root"
    group = "root"
    mode = "0600"
    encoding = "base64"
    
    [nexus-key]
    source = "nexus-key.age"
    target = "/run/aegis/nexus-key"
    user = "root"
    group = "root"
    mode = "0400"
    
    [secrets.myservice-token]
    source = "secrets/myservice-token.age"
    target = "/run/myservice/token"
    user = "myservice"
    group = "myservice"
    mode = "0600"
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore


# Default deployment settings for different secret types
# All paths under /run/aegis/ for safe decryption - NixOS config handles final placement
DEFAULTS = {
    "ssh-host-keys": {
        "target_dir": "/run/aegis/ssh",
        "user": "root",
        "group": "root",
        "mode": "0600",  # For private keys; public keys get 0644
    },
    "keytab": {
        "target": "/run/aegis/keytab",
        "user": "root",
        "group": "root",
        "mode": "0600",
    },
    "nexus-key": {
        "target": "/run/aegis/nexus-key",
        "user": "root",
        "group": "root",
        "mode": "0400",
    },
    "secret": {
        "user": "root",
        "group": "root",
        "mode": "0400",
    },
}


@dataclass
class SecretEntry:
    """A single secret entry in the manifest."""
    source: str                    # Relative path to .age file
    target: str | None = None      # Target path (or target_dir for bundles)
    target_dir: str | None = None  # For bundles like SSH keys
    user: str = "root"
    group: str = "root"
    mode: str = "0400"
    encoding: str | None = None    # "base64" for binary secrets
    key_types: list[str] | None = None  # For SSH keys: which types are included
    
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"source": self.source}
        if self.target:
            d["target"] = self.target
        if self.target_dir:
            d["target_dir"] = self.target_dir
        d["user"] = self.user
        d["group"] = self.group
        d["mode"] = self.mode
        if self.encoding:
            d["encoding"] = self.encoding
        if self.key_types:
            d["key_types"] = self.key_types
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> "SecretEntry":
        return cls(
            source=data["source"],
            target=data.get("target"),
            target_dir=data.get("target_dir"),
            user=data.get("user", "root"),
            group=data.get("group", "root"),
            mode=data.get("mode", "0400"),
            encoding=data.get("encoding"),
            key_types=data.get("key_types"),
        )


@dataclass
class HostSecretsManifest:
    """Manifest of all secrets for a host.
    
    This is stored at build/hosts/<hostname>/secrets.toml and contains
    metadata for all secrets that should be deployed to the host.
    """
    hostname: str
    ssh_host_keys: SecretEntry | None = None
    keytab: SecretEntry | None = None
    nexus_key: SecretEntry | None = None
    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        
        if self.ssh_host_keys:
            d["ssh-host-keys"] = self.ssh_host_keys.to_dict()
        if self.keytab:
            d["keytab"] = self.keytab.to_dict()
        if self.nexus_key:
            d["nexus-key"] = self.nexus_key.to_dict()
        if self.secrets:
            d["secrets"] = {
                name: entry.to_dict() for name, entry in self.secrets.items()
            }
        
        return d
    
    @classmethod
    def from_dict(cls, hostname: str, data: dict) -> "HostSecretsManifest":
        manifest = cls(hostname=hostname)
        
        if "ssh-host-keys" in data:
            manifest.ssh_host_keys = SecretEntry.from_dict(data["ssh-host-keys"])
        if "keytab" in data:
            manifest.keytab = SecretEntry.from_dict(data["keytab"])
        if "nexus-key" in data:
            manifest.nexus_key = SecretEntry.from_dict(data["nexus-key"])
        if "secrets" in data:
            manifest.secrets = {
                name: SecretEntry.from_dict(entry_data)
                for name, entry_data in data["secrets"].items()
            }
        
        return manifest


def load_host_manifest(build_path: Path, hostname: str) -> HostSecretsManifest:
    """Load a host's secrets manifest, creating empty one if not exists."""
    manifest_path = build_path / "hosts" / hostname / "secrets.toml"
    
    if manifest_path.exists():
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
        return HostSecretsManifest.from_dict(hostname, data)
    
    return HostSecretsManifest(hostname=hostname)


def save_host_manifest(build_path: Path, manifest: HostSecretsManifest) -> Path:
    """Save a host's secrets manifest."""
    manifest_path = build_path / "hosts" / manifest.hostname / "secrets.toml"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(manifest_path, "wb") as f:
        tomli_w.dump(manifest.to_dict(), f)
    
    return manifest_path


# =============================================================================
# DNSSEC Manifest (role-based, not host-based)
# =============================================================================

@dataclass 
class DnssecKeyEntry:
    """A single DNSSEC key file entry."""
    source: str
    target: str
    user: str = "root"
    group: str = "root"
    mode: str = "0400"
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "user": self.user,
            "group": self.group,
            "mode": self.mode,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "DnssecKeyEntry":
        return cls(
            source=data["source"],
            target=data["target"],
            user=data.get("user", "root"),
            group=data.get("group", "root"),
            mode=data.get("mode", "0400"),
        )


@dataclass
class DnssecManifest:
    """Manifest for a domain's DNSSEC keys."""
    domain: str
    role: str                      # dns-master-<domain>
    algorithm: str
    algorithm_num: int
    keytag: int
    public_key: DnssecKeyEntry | None = None
    private_key: DnssecKeyEntry | None = None
    ds_record: DnssecKeyEntry | None = None
    
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "domain": self.domain,
            "role": self.role,
            "algorithm": self.algorithm,
            "algorithm_num": self.algorithm_num,
            "keytag": self.keytag,
        }
        
        if self.public_key:
            d["public-key"] = self.public_key.to_dict()
        if self.private_key:
            d["private-key"] = self.private_key.to_dict()
        if self.ds_record:
            d["ds-record"] = self.ds_record.to_dict()
        
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> "DnssecManifest":
        manifest = cls(
            domain=data["domain"],
            role=data["role"],
            algorithm=data["algorithm"],
            algorithm_num=data["algorithm_num"],
            keytag=data["keytag"],
        )
        
        if "public-key" in data:
            manifest.public_key = DnssecKeyEntry.from_dict(data["public-key"])
        if "private-key" in data:
            manifest.private_key = DnssecKeyEntry.from_dict(data["private-key"])
        if "ds-record" in data:
            manifest.ds_record = DnssecKeyEntry.from_dict(data["ds-record"])
        
        return manifest


def load_dnssec_manifest(build_path: Path, domain: str) -> DnssecManifest | None:
    """Load a domain's DNSSEC manifest."""
    safe_domain = domain.replace(".", "_")
    manifest_path = build_path / "dnssec" / safe_domain / "secrets.toml"
    
    if not manifest_path.exists():
        return None
    
    with open(manifest_path, "rb") as f:
        data = tomllib.load(f)
    return DnssecManifest.from_dict(data)


def save_dnssec_manifest(build_path: Path, manifest: DnssecManifest) -> Path:
    """Save a domain's DNSSEC manifest."""
    safe_domain = manifest.domain.replace(".", "_")
    manifest_path = build_path / "dnssec" / safe_domain / "secrets.toml"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(manifest_path, "wb") as f:
        tomli_w.dump(manifest.to_dict(), f)
    
    return manifest_path


# =============================================================================
# Helper functions for creating entries with defaults
# =============================================================================

def make_ssh_host_keys_entry(
    key_types: list[str],
    target_dir: str | None = None,
    user: str | None = None,
    group: str | None = None,
    mode: str | None = None,
) -> SecretEntry:
    """Create an SSH host keys manifest entry with defaults."""
    defaults = DEFAULTS["ssh-host-keys"]
    return SecretEntry(
        source="ssh-host-keys.age",
        target_dir=target_dir or defaults["target_dir"],
        user=user or defaults["user"],
        group=group or defaults["group"],
        mode=mode or defaults["mode"],
        key_types=key_types,
    )


def make_keytab_entry(
    target: str | None = None,
    user: str | None = None,
    group: str | None = None,
    mode: str | None = None,
) -> SecretEntry:
    """Create a keytab manifest entry with defaults."""
    defaults = DEFAULTS["keytab"]
    return SecretEntry(
        source="keytab.age",
        target=target or defaults["target"],
        user=user or defaults["user"],
        group=group or defaults["group"],
        mode=mode or defaults["mode"],
        encoding="base64",
    )


def make_nexus_key_entry(
    target: str | None = None,
    user: str | None = None,
    group: str | None = None,
    mode: str | None = None,
) -> SecretEntry:
    """Create a Nexus key manifest entry with defaults."""
    defaults = DEFAULTS["nexus-key"]
    return SecretEntry(
        source="nexus-key.age",
        target=target or defaults["target"],
        user=user or defaults["user"],
        group=group or defaults["group"],
        mode=mode or defaults["mode"],
    )


def make_secret_entry(
    name: str,
    target: str,
    user: str | None = None,
    group: str | None = None,
    mode: str | None = None,
    encoding: str | None = None,
) -> SecretEntry:
    """Create a generic secret manifest entry."""
    defaults = DEFAULTS["secret"]
    return SecretEntry(
        source=f"secrets/{name}.age",
        target=target,
        user=user or defaults["user"],
        group=group or defaults["group"],
        mode=mode or defaults["mode"],
        encoding=encoding,
    )


def make_dnssec_entry(
    domain: str,
    algorithm: str,
    algorithm_num: int,
    keytag: int,
    target_dir: str | None = None,
    user: str | None = None,
    group: str | None = None,
) -> DnssecManifest:
    """Create a DNSSEC manifest with default target paths."""
    # Default target directory under /run/aegis for safe decryption
    if target_dir is None:
        target_dir = f"/run/aegis/dnssec/{domain}"
    
    _user = user or "root"
    _group = group or "root"
    
    return DnssecManifest(
        domain=domain,
        role=f"dns-master-{domain}",
        algorithm=algorithm,
        algorithm_num=algorithm_num,
        keytag=keytag,
        public_key=DnssecKeyEntry(
            source="ksk.key.age",
            target=f"{target_dir}/ksk.key",
            user=_user,
            group=_group,
            mode="0644",  # Public key can be world-readable
        ),
        private_key=DnssecKeyEntry(
            source="ksk.private.age",
            target=f"{target_dir}/ksk.private",
            user=_user,
            group=_group,
            mode="0400",  # Private key must be protected
        ),
        ds_record=DnssecKeyEntry(
            source="ksk.ds.age",
            target=f"{target_dir}/ksk.ds",
            user=_user,
            group=_group,
            mode="0644",  # DS record can be world-readable
        ),
    )
