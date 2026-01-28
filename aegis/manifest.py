"""Manifest handling for user secrets with privacy-preserving hashed filenames.

The manifest maps opaque hashed filenames to their actual secret names and metadata.
It's encrypted for both the host (for decryption) and the user (for auditing).

Example manifest structure:
    secrets:
      a1b2c3d4e5f6.age:
        name: GITHUB_TOKEN
        type: env
        created: 2024-01-15T10:30:00Z
      f7g8h9i0j1k2.age:
        name: ssh_config
        type: file
        target: ~/.ssh/config
        mode: "0600"
        created: 2024-01-15T10:30:00Z
"""

import hashlib
import secrets as py_secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class SecretEntry:
    """A single secret entry in the manifest."""
    name: str
    secret_type: str  # "env" or "file"
    created: datetime
    # Optional file-specific fields
    target: Optional[str] = None
    mode: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for YAML serialization."""
        d = {
            "name": self.name,
            "type": self.secret_type,
            "created": self.created.isoformat(),
        }
        if self.target:
            d["target"] = self.target
        if self.mode:
            d["mode"] = self.mode
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> "SecretEntry":
        """Create from dictionary."""
        created = data.get("created")
        if isinstance(created, str):
            created = datetime.fromisoformat(created)
        elif created is None:
            created = datetime.now(timezone.utc)
            
        return cls(
            name=data["name"],
            secret_type=data["type"],
            created=created,
            target=data.get("target"),
            mode=data.get("mode"),
        )


@dataclass
class Manifest:
    """User secrets manifest mapping hashed filenames to secret metadata."""
    
    # Map of hashed filename -> secret entry
    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    
    # Internal: reverse lookup for finding existing entries by name+type
    _by_name: dict[tuple[str, str], str] = field(default_factory=dict, repr=False)
    
    def __post_init__(self):
        """Build reverse lookup index."""
        self._rebuild_index()
    
    def _rebuild_index(self):
        """Rebuild the reverse lookup index."""
        self._by_name = {}
        for hashed_name, entry in self.secrets.items():
            key = (entry.name, entry.secret_type)
            self._by_name[key] = hashed_name
    
    def get_hashed_name(self, name: str, secret_type: str) -> Optional[str]:
        """Get existing hashed filename for a secret, or None if not in manifest."""
        return self._by_name.get((name, secret_type))
    
    def add_or_update(
        self,
        name: str,
        secret_type: str,
        target: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> str:
        """Add a new secret or update existing. Returns the hashed filename.
        
        If the secret already exists (same name + type), updates metadata
        and returns the existing hashed name for idempotency.
        """
        existing_hash = self.get_hashed_name(name, secret_type)
        
        if existing_hash:
            # Update existing entry
            entry = self.secrets[existing_hash]
            if target is not None:
                entry.target = target
            if mode is not None:
                entry.mode = mode
            return existing_hash
        
        # Create new entry with random hash
        hashed_name = generate_hash()
        entry = SecretEntry(
            name=name,
            secret_type=secret_type,
            created=datetime.now(timezone.utc),
            target=target,
            mode=mode,
        )
        
        self.secrets[hashed_name] = entry
        self._by_name[(name, secret_type)] = hashed_name
        
        return hashed_name
    
    def remove(self, name: str, secret_type: str) -> Optional[str]:
        """Remove a secret from the manifest. Returns hashed name if found."""
        hashed_name = self.get_hashed_name(name, secret_type)
        if hashed_name:
            del self.secrets[hashed_name]
            del self._by_name[(name, secret_type)]
            return hashed_name
        return None
    
    def list_secrets(self, secret_type: Optional[str] = None) -> list[tuple[str, SecretEntry]]:
        """List all secrets, optionally filtered by type.
        
        Returns list of (hashed_name, entry) tuples.
        """
        result = []
        for hashed_name, entry in self.secrets.items():
            if secret_type is None or entry.secret_type == secret_type:
                result.append((hashed_name, entry))
        return sorted(result, key=lambda x: x[1].name)
    
    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        data = {
            "secrets": {
                hashed_name: entry.to_dict()
                for hashed_name, entry in self.secrets.items()
            }
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=True)
    
    @classmethod
    def from_yaml(cls, content: str) -> "Manifest":
        """Parse from YAML string."""
        data = yaml.safe_load(content) or {}
        secrets_data = data.get("secrets", {})
        
        secrets = {}
        for hashed_name, entry_data in secrets_data.items():
            secrets[hashed_name] = SecretEntry.from_dict(entry_data)
        
        manifest = cls(secrets=secrets)
        return manifest
    
    @classmethod
    def empty(cls) -> "Manifest":
        """Create an empty manifest."""
        return cls()


def generate_hash() -> str:
    """Generate a random hash for a secret filename.
    
    Uses 8 bytes of randomness = 16 hex chars, giving us
    ~18 quintillion possibilities. Collision probability
    is negligible for any reasonable number of secrets.
    """
    return py_secrets.token_hex(8)


def hash_filename(name: str, secret_type: str, salt: Optional[str] = None) -> str:
    """Generate a deterministic hash for a secret name.
    
    This is an alternative to random hashes - useful if you want
    the same secret to always get the same hashed name (for debugging).
    
    NOT RECOMMENDED for production as it allows correlation attacks
    if the salt is known.
    """
    data = f"{secret_type}:{name}"
    if salt:
        data = f"{salt}:{data}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def load_manifest(manifest_path: Path, decrypt_fn) -> Manifest:
    """Load and decrypt a manifest file.
    
    Args:
        manifest_path: Path to the encrypted manifest.age file
        decrypt_fn: Function that takes a Path and returns decrypted content
        
    Returns:
        Manifest object
    """
    if not manifest_path.exists():
        return Manifest.empty()
    
    content = decrypt_fn(manifest_path)
    return Manifest.from_yaml(content)


def save_manifest(
    manifest: Manifest,
    manifest_path: Path,
    encrypt_fn,
    recipients: list[str],
) -> None:
    """Encrypt and save a manifest file.
    
    Args:
        manifest: The manifest to save
        manifest_path: Path to write the encrypted manifest.age file
        encrypt_fn: Function that takes (content, recipients, path)
        recipients: List of age public keys to encrypt for
    """
    content = manifest.to_yaml()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    encrypt_fn(content, recipients, manifest_path)
