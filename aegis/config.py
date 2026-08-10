"""Configuration management for aegis-secrets repo.

Layout::

    src/        source of truth: what should exist, and where it should land
    keys/       admin recipient set, role and user private keys
    deploy/     generated, host-targeted output (was: build/)

The goal is that ``deploy/`` is a function of ``src/`` plus existing key
material.  Anything that describes *intent* — which hosts exist, what services
they run, where a decrypted secret belongs and who owns it — lives in ``src/``.
``deploy/`` holds ciphertext and the derived per-host manifest, nothing else.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore

from .errors import ConfigError


#: Manifest sections that a host may set placement for.  ``secret:<name>``
#: keys are also accepted, for entries under ``[secrets]``.
PLACEMENT_KINDS = ("ssh-host-keys", "keytab", "nexus-key")


@dataclass
class Placement:
    """Where a decrypted secret belongs on the target host.

    Every field is optional; unset fields fall back to the built-in defaults in
    :mod:`aegis.host_secrets`.  Placement lives in ``src/`` so that the manifest
    in ``deploy/`` can be regenerated from scratch without losing it.
    """
    target: str | None = None
    target_dir: str | None = None
    user: str | None = None
    group: str | None = None
    mode: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            k: v
            for k, v in (
                ("target", self.target),
                ("target_dir", self.target_dir),
                ("user", self.user),
                ("group", self.group),
                ("mode", self.mode),
            )
            if v is not None
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Placement":
        return cls(
            target=data.get("target"),
            target_dir=data.get("target_dir"),
            user=data.get("user"),
            group=data.get("group"),
            mode=data.get("mode"),
        )

    def is_empty(self) -> bool:
        return not self.to_dict()


#: A host Aegis fully manages.  The default, and the only status for which a
#: missing master key or missing deployed secrets is a problem.
STATUS_ACTIVE = "active"

#: Declared, but not yet initialised -- no master key, nothing deployed.  A
#: placeholder for a host that is coming, so that roles and realms can name it
#: before it exists.
STATUS_PENDING = "pending"

#: Decommissioned.  Kept so the record of what it once held is not lost, but
#: it must no longer be a recipient of anything: whatever it could read should
#: be treated as disclosed and rotated.
STATUS_RETIRED = "retired"

#: A real host that Aegis does not deliver secrets to -- a container whose
#: secrets come from its host, or a machine managed by someone else.  It may
#: still legitimately appear in a realm or a role.
STATUS_EXTERNAL = "external"

HOST_STATUSES = (STATUS_ACTIVE, STATUS_PENDING, STATUS_RETIRED, STATUS_EXTERNAL)

#: Statuses for which Aegis builds and deploys host secrets.
DEPLOYING_STATUSES = (STATUS_ACTIVE,)


@dataclass
class HostConfig:
    """Configuration for a host.

    Attributes:
        hostname: The host's name
        age_pubkey: The host's master key (age public key format, e.g. "age1...").
                    This is the key used to encrypt secrets FOR this host.
                    The host uses the corresponding private key to decrypt.
        services: Kerberos services this host provides
        filesystem_keys: Filesystem encryption keys
        placement: Per-secret deployment metadata, keyed by manifest section
                   ("ssh-host-keys", "keytab", "nexus-key") or "secret:<name>"
        extra_secrets: Additional secrets with metadata
    """
    hostname: str
    age_pubkey: str | None = None  # age public key for encrypting secrets to this host
    services: list[str] = field(default_factory=lambda: ["host", "ssh"])
    filesystem_keys: list[str] = field(default_factory=list)
    placement: dict[str, Placement] = field(default_factory=dict)
    extra_secrets: dict[str, Any] = field(default_factory=dict)
    status: str = STATUS_ACTIVE
    note: str = ""

    @property
    def deploys(self) -> bool:
        """Whether Aegis should build and deploy secrets for this host."""
        return self.status in DEPLOYING_STATUSES

    @classmethod
    def from_dict(cls, hostname: str, data: dict) -> "HostConfig":
        placement = {
            key: Placement.from_dict(value)
            for key, value in data.get("placement", {}).items()
            if isinstance(value, dict)
        }
        # An unrecognised status must not silently read as "active": that would
        # turn a typo into a host that quietly starts receiving secrets again.
        status = data.get("status", STATUS_ACTIVE)
        if status not in HOST_STATUSES:
            raise ConfigError(
                f"host {hostname}: unknown status {status!r}. "
                f"Expected one of: {', '.join(HOST_STATUSES)}"
            )
        return cls(
            hostname=hostname,
            age_pubkey=data.get("age_pubkey"),
            services=data.get("services", ["host", "ssh"]),
            filesystem_keys=data.get("filesystem_keys", []),
            placement=placement,
            extra_secrets=data.get("extra_secrets", {}),
            status=status,
            note=data.get("note", ""),
        )

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "services": self.services,
            "filesystem_keys": self.filesystem_keys,
            "extra_secrets": self.extra_secrets,
        }
        # Written only when it is not the default, so existing host files stay
        # byte-identical until somebody actually changes a host's status.
        if self.status != STATUS_ACTIVE:
            d["status"] = self.status
        if self.note:
            d["note"] = self.note
        if self.age_pubkey:
            d["age_pubkey"] = self.age_pubkey
        placement = {
            key: value.to_dict()
            for key, value in sorted(self.placement.items())
            if not value.is_empty()
        }
        if placement:
            d["placement"] = placement
        return d

    def placement_for(self, kind: str) -> Placement:
        """Placement for a manifest section, or an empty one if unset."""
        return self.placement.get(kind, Placement())

    def set_placement(self, kind: str, placement: Placement) -> None:
        if placement.is_empty():
            self.placement.pop(kind, None)
        else:
            self.placement[kind] = placement


@dataclass
class UserConfig:
    """Configuration for a user."""
    username: str
    hosts: list[str]
    repo_url: str | None = None
    public_key: str | None = None  # User's age public key for manifest encryption

    @classmethod
    def from_dict(cls, username: str, data: dict) -> "UserConfig":
        return cls(
            username=username,
            hosts=data.get("hosts", []),
            repo_url=data.get("repo_url"),
            public_key=data.get("public_key"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "hosts": self.hosts,
        }
        if self.repo_url:
            d["repo_url"] = self.repo_url
        if self.public_key:
            d["public_key"] = self.public_key
        return d


@dataclass
class RoleConfig:
    """Configuration for a role.

    Attributes:
        name: The role's name
        hosts: Member hosts, each of which holds a copy of the role key
        placement: Per-secret deployment metadata for the role's own secrets,
                   keyed ``secret:<name>``.  A role secret is encrypted once,
                   to the role, so where it lands is a property of the role
                   rather than of whichever host currently holds it.
    """
    name: str
    hosts: list[str] = field(default_factory=list)
    placement: dict[str, Placement] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "RoleConfig":
        # Support both old single-host format and new multi-host format
        if "hosts" in data:
            hosts = data["hosts"]
        elif "host" in data and data["host"]:
            hosts = [data["host"]]
        else:
            hosts = []
        placement = {
            key: Placement.from_dict(value)
            for key, value in data.get("placement", {}).items()
            if isinstance(value, dict)
        }
        return cls(name=name, hosts=hosts, placement=placement)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"hosts": self.hosts}
        placement = {
            key: value.to_dict()
            for key, value in sorted(self.placement.items())
            if not value.is_empty()
        }
        if placement:
            d["placement"] = placement
        return d

    def placement_for(self, kind: str) -> Placement:
        """Placement for one of the role's secrets, or an empty one if unset."""
        return self.placement.get(kind, Placement())

    def set_placement(self, kind: str, placement: Placement) -> None:
        if placement.is_empty():
            self.placement.pop(kind, None)
        else:
            self.placement[kind] = placement


@dataclass
class DnssecConfig:
    """Configuration for a domain's DNSSEC keys."""
    domain: str
    algorithm: str      # e.g., "ECDSAP256SHA256"
    algorithm_num: int  # e.g., 13
    keytag: int         # e.g., 11926

    @classmethod
    def from_dict(cls, domain: str, data: dict) -> "DnssecConfig":
        return cls(
            domain=data.get("domain", domain),
            algorithm=data.get("algorithm", ""),
            algorithm_num=data.get("algorithm_num", 0),
            keytag=data.get("keytag", 0),
        )

    def to_dict(self) -> dict:
        return {
            # Store the real domain name so the on-disk directory name (which
            # has dots replaced) never has to be reversed.
            "domain": self.domain,
            "algorithm": self.algorithm,
            "algorithm_num": self.algorithm_num,
            "keytag": self.keytag,
        }


def _safe_name(name: str) -> str:
    """Filesystem-safe form of a dotted name (domain, realm)."""
    return name.replace(".", "_")


class SecretsRepo:
    """Interface to the aegis-secrets repository."""

    #: Generated output directory.  ``build`` is the historical name and is
    #: still honoured if present, so an un-migrated repo keeps working.
    DEPLOY_DIRNAME = "deploy"
    LEGACY_DEPLOY_DIRNAME = "build"

    def __init__(self, path: Path):
        self.path = path
        self.src_path = path / "src"
        self.keys_path = path / "keys"

        deploy = path / self.DEPLOY_DIRNAME
        legacy = path / self.LEGACY_DEPLOY_DIRNAME
        if not deploy.exists() and legacy.exists():
            self.deploy_path = legacy
        else:
            self.deploy_path = deploy

    @property
    def build_path(self) -> Path:
        """Deprecated alias for :attr:`deploy_path`."""
        return self.deploy_path

    def uses_legacy_deploy_dir(self) -> bool:
        return self.deploy_path.name == self.LEGACY_DEPLOY_DIRNAME

    def ensure_structure(self) -> None:
        """Create the expected directory structure if missing."""
        (self.src_path / "hosts").mkdir(parents=True, exist_ok=True)
        (self.src_path / "roles").mkdir(parents=True, exist_ok=True)
        (self.src_path / "users").mkdir(parents=True, exist_ok=True)
        (self.src_path / "kerberos" / "realms").mkdir(parents=True, exist_ok=True)
        (self.keys_path / "admin").mkdir(parents=True, exist_ok=True)
        (self.keys_path / "users").mkdir(parents=True, exist_ok=True)
        (self.keys_path / "roles").mkdir(parents=True, exist_ok=True)
        self.deploy_path.mkdir(parents=True, exist_ok=True)

    # Admin keys

    def admin_keys_path(self) -> Path:
        """Directory holding the admin recipient set (one .pub per key)."""
        return self.keys_path / "admin"

    def legacy_admin_key_path(self) -> Path:
        """Historical single-file admin public key."""
        return self.keys_path / "admin.pub"

    # Host configuration

    def get_host_config(self, hostname: str) -> HostConfig | None:
        """Read host configuration."""
        config_path = self.src_path / "hosts" / f"{hostname}.toml"
        if not config_path.exists():
            return None

        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return HostConfig.from_dict(hostname, data)

    def set_host_config(self, config: HostConfig) -> None:
        """Write host configuration."""
        config_path = self.src_path / "hosts" / f"{config.hostname}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)

    def list_hosts(self) -> list[str]:
        """List all configured hosts, whatever their status."""
        hosts_dir = self.src_path / "hosts"
        if not hosts_dir.exists():
            return []
        return sorted(p.stem for p in hosts_dir.glob("*.toml"))

    def host_status(self, hostname: str) -> str:
        """A host's lifecycle status; ``active`` for anything unrecorded."""
        host_config = self.get_host_config(hostname)
        return host_config.status if host_config else STATUS_ACTIVE

    def list_deploying_hosts(self) -> list[str]:
        """Hosts Aegis should build and deploy secrets for.

        Use this, not :meth:`list_hosts`, anywhere the answer feeds encryption
        or deployment.  A retired host left in a recipient set is a key that
        can still read new secrets after the machine is gone.
        """
        return [h for h in self.list_hosts()
                if self.host_status(h) in DEPLOYING_STATUSES]

    # User configuration

    def get_user_config(self, username: str) -> UserConfig | None:
        """Read user configuration."""
        config_path = self.src_path / "users" / f"{username}.toml"
        if not config_path.exists():
            return None

        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return UserConfig.from_dict(username, data)

    def set_user_config(self, config: UserConfig) -> None:
        """Write user configuration."""
        config_path = self.src_path / "users" / f"{config.username}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)

    def list_users(self) -> list[str]:
        """List all configured users."""
        users_dir = self.src_path / "users"
        if not users_dir.exists():
            return []
        return sorted(p.stem for p in users_dir.glob("*.toml"))

    # Role configuration

    def get_role_config(self, role_name: str) -> RoleConfig | None:
        """Read role configuration."""
        config_path = self.src_path / "roles" / f"{role_name}.toml"
        if not config_path.exists():
            return None

        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return RoleConfig.from_dict(role_name, data)

    def set_role_config(self, config: RoleConfig) -> None:
        """Write role configuration."""
        config_path = self.src_path / "roles" / f"{config.name}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)

    def list_roles(self) -> list[str]:
        """List all configured roles."""
        roles_dir = self.src_path / "roles"
        if not roles_dir.exists():
            return []
        return sorted(p.stem for p in roles_dir.glob("*.toml"))

    # Deploy paths

    def host_deploy_path(self, hostname: str) -> Path:
        """Get the deploy output directory for a host."""
        return self.deploy_path / "hosts" / hostname

    def host_build_path(self, hostname: str) -> Path:
        """Deprecated alias for :meth:`host_deploy_path`."""
        return self.host_deploy_path(hostname)

    def list_deployed_hosts(self) -> list[str]:
        """Hosts that have output in deploy/, whether or not they're in src/."""
        hosts_dir = self.deploy_path / "hosts"
        if not hosts_dir.is_dir():
            return []
        return sorted(p.name for p in hosts_dir.iterdir() if p.is_dir())

    def resolve_user_allowed_hosts(self, user_config: "UserConfig") -> set[str]:
        """Compute the set of hosts a user is allowed to read secrets on.

        Supports the ``"*"`` sentinel in :attr:`UserConfig.hosts` as
        "every active host aegis manages", re-evaluated on each call.
        New hosts added after the user was configured are reachable on
        the next :func:`build_user_secrets` run.

        An explicit host alongside ``*`` is redundant (the wildcard
        supersedes it) but harmless — explicit entries are kept so the
        config remains self-documenting about who is supposed to read.

        Retired or externally-managed hosts are not in this set: a user
        with ``*`` should not gain access to hosts Aegis has stopped
        managing (``list_deploying_hosts`` filters those out). Aegis's
        ``check`` command still flags obsolete on-disk artefacts so an
        explicit cleanup is possible.
        """
        explicit = {h for h in user_config.hosts if h != "*"}
        if "*" not in user_config.hosts:
            return explicit
        return explicit | set(self.list_deploying_hosts())

    def roles_deploy_path(self) -> Path:
        """Directory holding role public keys."""
        return self.deploy_path / "roles"

    def role_build_path(self, role_name: str | None = None) -> Path:
        """Deprecated alias for :meth:`roles_deploy_path`.

        The role name was never used; callers append it themselves.
        """
        return self.roles_deploy_path()

    def role_pubkey_path(self, role_name: str) -> Path:
        """Public key for a role."""
        return self.roles_deploy_path() / f"{role_name}.pub"

    def role_key_path(self, role_name: str) -> Path:
        """Get the path to the admin-encrypted role private key."""
        return self.keys_path / "roles" / f"{role_name}.age"

    def host_role_key_path(self, hostname: str, role_name: str) -> Path:
        """Get the path to a host's copy of a role private key."""
        return self.host_deploy_path(hostname) / "roles" / f"{role_name}.age"

    def role_deploy_path(self, role_name: str) -> Path:
        """Directory holding a role's own output, beside its public key.

        A sibling of ``deploy/roles/<role>.pub`` rather than a nesting of it:
        the public key is a file, so the directory cannot share its name.
        """
        return self.roles_deploy_path() / role_name

    def role_secrets_path(self, role_name: str) -> Path:
        """Directory holding secrets encrypted to a role."""
        return self.role_deploy_path(role_name) / "secrets"

    def role_secret_path(self, role_name: str, secret_name: str) -> Path:
        """A single secret encrypted to a role.

        One file, whatever the membership: the role key is what decrypts it,
        so adding a host means giving that host the role key, not re-encrypting
        the secret.
        """
        return self.role_secrets_path(role_name) / f"{secret_name}.age"

    def list_role_secrets(self, role_name: str) -> list[str]:
        """Names of the secrets encrypted to a role."""
        secrets_dir = self.role_secrets_path(role_name)
        if not secrets_dir.is_dir():
            return []
        return sorted(p.stem for p in secrets_dir.glob("*.age"))

    def kdc_deploy_path(self) -> Path:
        """Directory holding per-realm KDC principal bundles."""
        return self.deploy_path / "kdc"

    # User keys

    def user_key_path(self, username: str) -> Path:
        """Get the path to a user's private key (encrypted)."""
        return self.keys_path / "users" / f"{username}.age"

    def user_pubkey_path(self, username: str) -> Path:
        """Get the path to a user's public key."""
        return self.keys_path / "users" / f"{username}.pub"

    # Kerberos

    def realms_path(self) -> Path:
        return self.src_path / "kerberos" / "realms"

    def realm_path(self, realm: str) -> Path:
        return self.realms_path() / realm

    def realm_config_path(self, realm: str) -> Path:
        return self.realm_path(realm) / "realm.toml"

    def realm_key_path(self, realm: str) -> Path:
        return self.realm_path(realm) / "realm.key.age"

    def realm_principals_path(self, realm: str) -> Path:
        return self.realm_path(realm) / "principals"

    def realm_previous_principals_path(self, realm: str) -> Path:
        """Keys retained from before a rekey, so keytabs can carry both kvnos.

        A separate directory rather than a filename suffix, so that listing
        current principals stays a plain non-recursive glob.
        """
        return self.realm_principals_path(realm) / "previous"

    def list_realms(self) -> list[str]:
        realms_dir = self.realms_path()
        if not realms_dir.is_dir():
            return []
        return sorted(p.name for p in realms_dir.iterdir() if p.is_dir())

    # DNSSEC configuration

    def dnssec_src_path(self, domain: str) -> Path:
        """Get the source config directory for a domain's DNSSEC keys."""
        return self.src_path / "dnssec" / _safe_name(domain)

    def dnssec_deploy_path(self, domain: str) -> Path:
        """Get the deploy output directory for a domain's DNSSEC keys."""
        return self.deploy_path / "dnssec" / _safe_name(domain)

    def dnssec_build_path(self, domain: str) -> Path:
        """Deprecated alias for :meth:`dnssec_deploy_path`."""
        return self.dnssec_deploy_path(domain)

    def get_dnssec_config(self, domain: str) -> DnssecConfig | None:
        """Read DNSSEC configuration for a domain."""
        config_path = self.dnssec_src_path(domain) / "config.toml"
        if not config_path.exists():
            return None

        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return DnssecConfig.from_dict(domain, data)

    def set_dnssec_config(self, config: DnssecConfig) -> None:
        """Write DNSSEC configuration for a domain."""
        config_path = self.dnssec_src_path(config.domain) / "config.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)

    def list_dnssec_domains(self) -> list[str]:
        """List all domains with DNSSEC keys configured.

        The real domain name is read from each config file rather than
        reversing the directory name, which is not a reversible mapping for
        domains containing underscores.
        """
        dnssec_dir = self.src_path / "dnssec"
        if not dnssec_dir.exists():
            return []

        domains = []
        for entry in sorted(dnssec_dir.iterdir()):
            if not entry.is_dir():
                continue
            config_path = entry / "config.toml"
            name = None
            if config_path.exists():
                try:
                    with open(config_path, "rb") as f:
                        name = tomllib.load(f).get("domain")
                except (OSError, tomllib.TOMLDecodeError):
                    name = None
            domains.append(name or entry.name.replace("_", "."))
        return domains
