"""Host secrets manifest management.

This module manages the secrets.toml manifest file for each host, which
contains metadata about all secrets and their deployment configuration.

The manifest is stored at deploy/hosts/<hostname>/secrets.toml and can be
imported by NixOS to configure services with the correct paths.

Example manifest:

    [[ssh-host-keys]]
    source = "ssh/ssh_host_ed25519_key.age"
    target = "ssh_host_ed25519_key"
    target_dir = "/run/aegis/ssh"
    user = "root"
    group = "root"
    mode = "0600"
    type = "ed25519"

    [[ssh-host-keys]]
    source = "ssh/ssh_host_ecdsa_key.age"
    target = "ssh_host_ecdsa_key"
    target_dir = "/run/aegis/ssh"
    user = "root"
    group = "root"
    mode = "0600"
    type = "ecdsa"

    [keytab]
    source = "keytab.age"
    target = "/run/aegis/keytab"
    user = "root"
    group = "root"
    mode = "0600"
    
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

    # A secret encrypted to a role rather than to this host: one ciphertext,
    # shared by every member, decrypted in phase 2 with the role key.
    [secrets.ldap-bind-password]
    source = "../../roles/authentik/secrets/ldap-bind-password.age"
    target = "/run/authentik/ldap-password"
    user = "authentik"
    group = "authentik"
    mode = "0400"
    role = "authentik"
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore

from .config import Placement, SecretsRepo


# Default deployment settings for different secret types
# All paths under /run/aegis/ for safe decryption - NixOS config handles final placement
DEFAULTS = {
    "ssh-host-keys": {
        "target_dir": "/run/aegis/ssh",
        "user": "root",
        "group": "root",
        "mode": "0600",
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
    type: str | None = None        # SSH key type ("ed25519", "ecdsa", "rsa")
    # Set when the secret is encrypted to a role rather than to this host.
    # The NixOS module reads it as "decrypt in phase 2, with the role key this
    # host unwrapped in phase 1" -- there is no per-host copy to point at.
    role: str | None = None

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
        if self.type:
            d["type"] = self.type
        if self.role:
            d["role"] = self.role
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
            type=data.get("type"),
            role=data.get("role"),
        )


@dataclass
class HostSecretsManifest:
    """Manifest of all secrets for a host.

    This is stored at deploy/hosts/<hostname>/secrets.toml and contains
    metadata for all secrets that should be deployed to the host.
    """
    hostname: str
    ssh_host_keys: list[SecretEntry] = field(default_factory=list)
    keytab: SecretEntry | None = None
    nexus_key: SecretEntry | None = None
    secrets: dict[str, SecretEntry] = field(default_factory=dict)
    roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}

        if self.ssh_host_keys:
            d["ssh-host-keys"] = [entry.to_dict() for entry in self.ssh_host_keys]
        if self.keytab:
            d["keytab"] = self.keytab.to_dict()
        if self.nexus_key:
            d["nexus-key"] = self.nexus_key.to_dict()
        if self.secrets:
            d["secrets"] = {
                name: entry.to_dict() for name, entry in self.secrets.items()
            }
        if self.roles:
            d["roles"] = self.roles

        return d

    @classmethod
    def from_dict(cls, hostname: str, data: dict) -> "HostSecretsManifest":
        manifest = cls(hostname=hostname)

        if "ssh-host-keys" in data:
            manifest.ssh_host_keys = [
                SecretEntry.from_dict(e) for e in data["ssh-host-keys"]
            ]
        if "keytab" in data:
            manifest.keytab = SecretEntry.from_dict(data["keytab"])
        if "nexus-key" in data:
            manifest.nexus_key = SecretEntry.from_dict(data["nexus-key"])
        if "secrets" in data:
            manifest.secrets = {
                name: SecretEntry.from_dict(entry_data)
                for name, entry_data in data["secrets"].items()
            }
        if "roles" in data:
            manifest.roles = data["roles"]

        return manifest


def load_host_manifest(deploy_path: Path, hostname: str) -> HostSecretsManifest:
    """Load a host's secrets manifest, creating empty one if not exists."""
    manifest_path = deploy_path / "hosts" / hostname / "secrets.toml"
    
    if manifest_path.exists():
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
        return HostSecretsManifest.from_dict(hostname, data)
    
    return HostSecretsManifest(hostname=hostname)


def save_host_manifest(deploy_path: Path, manifest: HostSecretsManifest) -> Path:
    """Save a host's secrets manifest."""
    manifest_path = deploy_path / "hosts" / manifest.hostname / "secrets.toml"
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


def load_dnssec_manifest(deploy_path: Path, domain: str) -> DnssecManifest | None:
    """Load a domain's DNSSEC manifest."""
    safe_domain = domain.replace(".", "_")
    manifest_path = deploy_path / "dnssec" / safe_domain / "secrets.toml"
    
    if not manifest_path.exists():
        return None
    
    with open(manifest_path, "rb") as f:
        data = tomllib.load(f)
    return DnssecManifest.from_dict(data)


def save_dnssec_manifest(deploy_path: Path, manifest: DnssecManifest) -> Path:
    """Save a domain's DNSSEC manifest."""
    safe_domain = manifest.domain.replace(".", "_")
    manifest_path = deploy_path / "dnssec" / safe_domain / "secrets.toml"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(manifest_path, "wb") as f:
        tomli_w.dump(manifest.to_dict(), f)
    
    return manifest_path


# =============================================================================
# Helper functions for creating entries with defaults
# =============================================================================

def make_ssh_host_keys_entries(
    stems: list[str],
    placement: Placement | None = None,
    key_types: list[str] | None = None,
) -> list[SecretEntry]:
    """Create SSH host key manifest entries, one per private key file.

    Each entry covers a single age-encrypted private key.  The source path
    follows the convention ``ssh/<stem>.age`` and the target filename is the
    stem itself (i.e. the name sshd expects, e.g. ``ssh_host_ed25519_key``).

    Args:
        stems: List of file stems (e.g. ``["ssh_host_ed25519_key"]``)
        placement: Per-host overrides from ``src/hosts/<host>.toml``
        key_types: Optional list of SSH key types parallel to ``stems``
                   (e.g. ``["ed25519"]``).  When provided each entry will
                   include a ``type`` field that the ``fudoniten/aegis``
                   NixOS module uses to configure OpenSSH.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["ssh-host-keys"]
    entries = []
    for i, stem in enumerate(stems):
        key_type = key_types[i] if key_types and i < len(key_types) else None
        entries.append(SecretEntry(
            source=f"ssh/{stem}.age",
            target=stem,
            target_dir=placement.target_dir or defaults["target_dir"],
            user=placement.user or defaults["user"],
            group=placement.group or defaults["group"],
            mode=placement.mode or defaults["mode"],
            type=key_type,
        ))
    return entries


def make_keytab_entry(placement: Placement | None = None) -> SecretEntry:
    """Create a keytab manifest entry.

    No ``encoding`` is set: keytabs are stored as raw bytes now that the
    crypto layer is binary clean.  The old ``base64`` encoding was never
    honoured by the NixOS module, so keytabs deployed as the literal string
    ``base64:...`` rather than a keytab.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["keytab"]
    return SecretEntry(
        source="keytab.age",
        target=placement.target or defaults["target"],
        user=placement.user or defaults["user"],
        group=placement.group or defaults["group"],
        mode=placement.mode or defaults["mode"],
    )


def make_nexus_key_entry(placement: Placement | None = None) -> SecretEntry:
    """Create a Nexus key manifest entry with defaults."""
    placement = placement or Placement()
    defaults = DEFAULTS["nexus-key"]
    return SecretEntry(
        source="nexus-key.age",
        target=placement.target or defaults["target"],
        user=placement.user or defaults["user"],
        group=placement.group or defaults["group"],
        mode=placement.mode or defaults["mode"],
    )


def make_secret_entry(
    name: str,
    placement: Placement | None = None,
    encoding: str | None = None,
) -> SecretEntry:
    """Create a generic secret manifest entry.

    Falls back to ``/run/aegis/secrets/<name>`` when the host declares no
    target, so a secret is never silently left without a destination.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["secret"]
    return SecretEntry(
        source=f"secrets/{name}.age",
        target=placement.target or f"/run/aegis/secrets/{name}",
        user=placement.user or defaults["user"],
        group=placement.group or defaults["group"],
        mode=placement.mode or defaults["mode"],
        encoding=encoding,
    )


def make_role_secret_entry(
    role: str,
    name: str,
    placement: Placement | None = None,
    encoding: str | None = None,
) -> SecretEntry:
    """Create a manifest entry pointing at a role's copy of a secret.

    The source is relative to the host's own directory, as every other entry
    is, and climbs out of it: there is exactly one ciphertext per role secret,
    at ``deploy/roles/<role>/secrets/<name>.age``, and every member host's
    manifest names that same file.  That is the point -- adding a host to the
    role is enough to give it the secret, with no re-encryption and no need
    for the plaintext ever again.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["secret"]
    return SecretEntry(
        source=f"../../roles/{role}/secrets/{name}.age",
        target=placement.target or f"/run/aegis/secrets/{name}",
        user=placement.user or defaults["user"],
        group=placement.group or defaults["group"],
        mode=placement.mode or defaults["mode"],
        encoding=encoding,
        role=role,
    )


def role_secret_entries(
    repo: SecretsRepo,
    hostname: str,
) -> tuple[dict[str, SecretEntry], list[str]]:
    """The role secrets a host should carry, and any name collisions found.

    A host gets every secret of every role it belongs to.  Names are the
    manifest's keys, so two roles publishing the same name -- or a role and
    the host itself -- would overwrite each other; those are reported instead
    of being resolved silently, since either answer loses a secret.
    """
    entries: dict[str, SecretEntry] = {}
    owner: dict[str, str] = {}
    conflicts: list[str] = []

    for role_name in repo.list_roles():
        role_config = repo.get_role_config(role_name)
        if role_config is None or hostname not in role_config.hosts:
            continue
        for name in repo.list_role_secrets(role_name):
            if name in entries:
                conflicts.append(
                    f"'{name}' is published by both role '{owner[name]}' and "
                    f"role '{role_name}'")
                continue
            owner[name] = role_name
            entries[name] = make_role_secret_entry(
                role=role_name,
                name=name,
                placement=role_config.placement_for(f"secret:{name}"),
            )

    return entries, conflicts


def reconcile_roles(
    repo: SecretsRepo,
    hostname: str,
    manifest: "HostSecretsManifest",
) -> list[str]:
    """Bring a manifest's role-derived parts in line with role membership.

    Two things follow from membership and neither is worth stating by hand:
    the list of roles whose keys the host unwraps in phase 1, and an entry for
    every secret those roles hold.  Both are recomputed here.

    Entries for a role the host no longer belongs to are dropped, so that
    ``aegis role remove-host`` actually stops the host deploying the role's
    secrets rather than leaving it pointing at a file it can no longer read.
    Host-local secrets are left alone; one that shadows a role secret keeps
    its place, since it is the more specific declaration.
    """
    # The roles a host *holds a key for*, not the ones it is listed under:
    # membership can be recorded before the key is written (a pending host),
    # and a manifest naming a role whose key file is absent fails at boot.
    roles_dir = repo.host_deploy_path(hostname) / "roles"
    manifest.roles = (
        sorted(f.stem for f in roles_dir.glob("*.age")) if roles_dir.is_dir() else []
    )

    wanted, conflicts = role_secret_entries(repo, hostname)

    for name, entry in list(manifest.secrets.items()):
        if entry.role and name not in wanted:
            del manifest.secrets[name]

    for name, entry in wanted.items():
        existing = manifest.secrets.get(name)
        if existing is not None and not existing.role:
            conflicts.append(
                f"'{name}' is both a role secret (role '{entry.role}') and a "
                f"secret of host {hostname}; the host's own copy is kept")
            continue
        manifest.secrets[name] = entry

    return conflicts


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
