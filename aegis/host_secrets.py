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

import re
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

# What ``ssh-keygen -t`` accepts, which is also what sshd will load as a host
# key.  ``[[ssh-host-keys]]`` means the identities sshd presents, so a type
# outside this set cannot belong there whatever else it may legitimately be:
# the NixOS module builds services.openssh.hostKeys from every entry carrying
# a type, and its sshd-keygen fallback regenerates a missing key by running
# ``ssh-keygen -t <type>``.
SSHD_HOST_KEY_TYPES = ("dsa", "ecdsa", "ecdsa-sk", "ed25519", "ed25519-sk", "rsa")


def _reject_non_sshd_types(entries: list[SecretEntry]) -> None:
    """Raise if any entry's ``type`` is not one sshd can present.

    A deploy key and an initrd key are both SSH keypairs and neither is an
    sshd host key.  Sweeping them into ``[[ssh-host-keys]]`` hands their
    private halves to sshd as host identities and breaks the fallback that
    regenerates a missing key.  They belong in ``[secrets]``, which deploys
    them on the same terms without offering them to sshd.
    """
    offenders = [
        entry for entry in entries
        if entry.type is not None and entry.type not in SSHD_HOST_KEY_TYPES
    ]
    if not offenders:
        return

    listed = ", ".join(f"{entry.target} ({entry.type})" for entry in offenders)
    raise ValueError(
        f"not an SSH key type: {listed}. [[ssh-host-keys]] is the list of "
        f"identities sshd presents, and ssh-keygen has no such type, so the "
        f"NixOS module cannot deploy or regenerate these. Valid types are "
        f"{', '.join(SSHD_HOST_KEY_TYPES)}. Keys that are not sshd host "
        f"identities (deploy, initrd) belong in [secrets]."
    )


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

    Raises:
        ValueError: if a supplied type is not one sshd can present.  Catching
            it here covers both producers -- ``aegis build ssh-keys`` and
            ``aegis ssh import`` -- rather than each having to remember.
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
    _reject_non_sshd_types(entries)
    return entries


def classify_ssh_stems(
    stems: list[str],
) -> tuple[list[tuple[str, str]], list[str]]:
    """Split ``ssh/`` file stems into host keys and everything else.

    A stem is an sshd host key when it is named ``ssh_host_<type>_key`` for a
    type sshd can actually present.  That is the convention every producer
    here writes, and it is the only signal available when rebuilding a
    manifest from what is on disk.

    Deriving the type by stripping affixes instead -- ``removeprefix
    ("ssh_host_").removesuffix("_key")`` -- is what wrote ``deploy_ed25519``
    and ``initrd_ed25519`` into production manifests: the prefix simply is not
    there to remove, so the whole stem became the "type".

    Returns:
        ``([(stem, type), ...], [stem, ...])`` -- host keys with their type,
        and the stems that are not host keys.
    """
    host_keys: list[tuple[str, str]] = []
    auxiliary: list[str] = []

    for stem in stems:
        match = re.fullmatch(r"ssh_host_(.+)_key", stem)
        if match and match.group(1) in SSHD_HOST_KEY_TYPES:
            host_keys.append((stem, match.group(1)))
        else:
            auxiliary.append(stem)

    return host_keys, auxiliary


def split_ssh_host_keys(
    entries: list[SecretEntry],
) -> tuple[list[SecretEntry], list[SecretEntry]]:
    """Partition ``[[ssh-host-keys]]`` into sshd identities and everything else.

    Manifests written before ``[[ssh-host-keys]]`` was enforced carry deploy
    and initrd keys in the list.  Rewriting a host's SSH keys is the natural
    moment to correct that, and the correction is mechanical: the misfiled
    entries move to ``[secrets]`` keeping their target, so nothing on disk
    changes and no key is regenerated.

    Untyped entries stay with the host keys.  The NixOS module filters them
    out before sshd sees them, so they are unused rather than wrong, and
    guessing at what they were meant to be would be worse than leaving them.
    """
    host_keys = [
        entry for entry in entries
        if entry.type is None or entry.type in SSHD_HOST_KEY_TYPES
    ]
    misfiled = [
        entry for entry in entries
        if entry.type is not None and entry.type not in SSHD_HOST_KEY_TYPES
    ]
    return host_keys, misfiled


def make_ssh_auxiliary_entries(
    stems: list[str],
    placement: Placement | None = None,
) -> dict[str, SecretEntry]:
    """Manifest entries for SSH keypairs that are *not* sshd host identities.

    The deploy and initrd keys are generated and delivered alongside the host
    keys and live in the same ``ssh/`` directory, but they are consumed by
    something other than sshd -- deploy-rs and the initramfs sshd, which is a
    separate server with its own configuration.  Declaring them under
    ``[secrets]`` rather than ``[[ssh-host-keys]]`` is what keeps them out of
    ``services.openssh.hostKeys``.

    They keep their existing on-disk target, so this is a change of
    declaration only: nothing moves, and no key has to be regenerated.

    Returns:
        Entries keyed by secret name -- the stem with underscores turned into
        hyphens, since the name becomes a systemd unit suffix.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["ssh-host-keys"]
    target_dir = placement.target_dir or defaults["target_dir"]

    return {
        stem.replace("_", "-"): SecretEntry(
            source=f"ssh/{stem}.age",
            target=f"{target_dir}/{stem}",
            user=placement.user or defaults["user"],
            group=placement.group or defaults["group"],
            mode=placement.mode or defaults["mode"],
        )
        for stem in stems
    }


def merge_ssh_host_keys_entries(
    existing: list[SecretEntry],
    new: list[SecretEntry],
) -> list[SecretEntry]:
    """Merge freshly imported SSH host key entries into a host's existing set.

    Importing one key at a time is the natural way to drive ``aegis ssh
    import`` from a shell loop, and assigning ``manifest.ssh_host_keys``
    outright makes each invocation silently discard the previous one's work:
    after ::

        for t in ed25519 ecdsa; do aegis ssh import "$h" --key "$h.$t.key"; done

    the manifest declares only ecdsa, while the ciphertext for both sits in
    ``deploy/hosts/<host>/ssh/``.  Nothing fails, and the NixOS module builds
    ``services.openssh.hostKeys`` from the manifest, so the host quietly comes
    up offering a single key type.

    Entries are keyed by ``target`` -- the filename sshd is handed -- so
    re-importing the same key replaces it in place and keeps its position.

    Raises:
        ValueError: if the merged set would carry a duplicate ``type``.  The
            NixOS module names its units ``aegis-ssh-<type>`` and collects them
            with ``listToAttrs``, so two entries of one type collapse into a
            single unit and the other's target is never written.  There is no
            case where that is what the caller wanted.
    """
    pending = {entry.target: entry for entry in new}

    merged = [pending.pop(entry.target, entry) for entry in existing]
    merged.extend(entry for entry in new if entry.target in pending)

    types = [entry.type for entry in merged if entry.type is not None]
    duplicates = sorted({t for t in types if types.count(t) > 1})
    if duplicates:
        offenders = ", ".join(
            f"{entry.target} ({entry.type})"
            for entry in merged if entry.type in duplicates
        )
        raise ValueError(
            f"duplicate SSH host key type(s) {', '.join(duplicates)}: {offenders}. "
            f"The NixOS module names units aegis-ssh-<type>, so these would "
            f"collapse into one unit and some keys would never be written. "
            f"Keys that are not sshd host identities (deploy, initrd) belong "
            f"in [secrets], not [[ssh-host-keys]]."
        )

    return merged


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


# The NixOS module renames a [secrets.<name>] entry to `secret-<name>` when it
# builds `aegis.secrets.manifest.targets`, and names its unit after that.  Only
# [keytab] and [nexus-key] escape the prefix, because they have their own
# manifest sections rather than living under [secrets].
#
# Callers get this wrong in a way that is quiet and expensive -- a `targets`
# lookup without the prefix simply misses, so the service is configured with
# nothing while Aegis goes on decrypting the secret perfectly well.  Both
# spellings live here so that the tools can print the reference rather than
# leaving it to be rediscovered.

def manifest_key(name: str) -> str:
    """The key `aegis.secrets.manifest.targets` holds this secret under."""
    return f"secret-{name}"


def decrypt_unit(name: str) -> str:
    """The systemd unit that writes this secret, for after= and requires=."""
    return f"aegis-{manifest_key(name)}.service"


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


def make_nebula_entries(
    network: str,
    *,
    with_key: bool,
    placement: Placement | None = None,
) -> dict[str, SecretEntry]:
    """Manifest entries for one Nebula network, keyed by secret name.

    Three files, and they go under ``[secrets]`` rather than getting a section
    of their own.  That is the point: the Aegis NixOS module already handles
    ``[secrets]`` generically and surfaces them through
    ``aegis.secrets.manifest.targets``, so Nebula needs no host-side change.

    The certificate and the CA certificate are public, and are shipped as
    ciphertext anyway.  Encrypting public data costs nothing; giving the host a
    second, unencrypted delivery path would cost a great deal.

    ``with_key`` is false for a host that generated its own private key and
    sent only the public half.  Aegis then has a certificate to deliver but no
    key, and must not imply otherwise by writing an entry that points at a file
    which does not exist.
    """
    placement = placement or Placement()
    defaults = DEFAULTS["secret"]
    # The service user the upstream NixOS module runs Nebula as.
    owner = placement.user or f"nebula-{network}"
    group = placement.group or owner
    base = placement.target_dir or "/run/aegis/nebula"

    entries = {
        f"nebula-{network}-cert": SecretEntry(
            source=f"nebula/{network}.crt.age",
            target=f"{base}/{network}.crt",
            user=owner,
            group=group,
            mode="0444",
        ),
        f"nebula-{network}-ca": SecretEntry(
            source=f"nebula/{network}-ca.crt.age",
            target=f"{base}/{network}-ca.crt",
            user=owner,
            group=group,
            mode="0444",
        ),
    }

    if with_key:
        entries[f"nebula-{network}-key"] = SecretEntry(
            source=f"nebula/{network}.key.age",
            target=f"{base}/{network}.key",
            user=owner,
            group=group,
            mode=placement.mode or defaults["mode"],
        )

    return entries


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
