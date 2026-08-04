"""Kerberos realm metadata and host/realm resolution.

A realm used to carry no metadata at all: encryption types and ticket
lifetimes were Python defaults, so a realm created with non-default etypes
would be silently re-instantiated with the wrong ones when building keytabs.
Realm state now lives in ``src/kerberos/realms/<REALM>/realm.toml``.

Host membership resolves as::

    host --(domain-<domain> role)--> domain --(realm.toml domains)--> realm

which reuses the ``domain-*`` roles already in the repo rather than
introducing a third place to record the same fact.  The FQDN used for
principals is ``<hostname>.<domain>``.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore

from .config import SecretsRepo
from .errors import RealmError

DEFAULT_ETYPES = ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"]
DEFAULT_MAX_TICKET_LIFETIME = "1w"
DEFAULT_MAX_RENEWABLE_LIFETIME = "1m"

#: Prefix of the roles that record domain membership.
DOMAIN_ROLE_PREFIX = "domain-"

KIND_INFRASTRUCTURE = "infrastructure"
KIND_HOST = "host"
KIND_SERVICE = "service"
KIND_CROSS_REALM = "cross-realm"


@dataclass
class PrincipalEntry:
    """Index entry for a principal stored in the realm."""
    kind: str = KIND_SERVICE
    host: str | None = None       # host whose keytab should include this
    peer: str | None = None       # for cross-realm: the other realm

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind}
        if self.host:
            d["host"] = self.host
        if self.peer:
            d["peer"] = self.peer
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "PrincipalEntry":
        return cls(
            kind=data.get("kind", KIND_SERVICE),
            host=data.get("host"),
            peer=data.get("peer"),
        )


@dataclass
class RealmConfig:
    """Contents of ``realm.toml``."""
    name: str
    etypes: list[str] = field(default_factory=lambda: list(DEFAULT_ETYPES))
    max_ticket_lifetime: str = DEFAULT_MAX_TICKET_LIFETIME
    max_renewable_lifetime: str = DEFAULT_MAX_RENEWABLE_LIFETIME
    domains: list[str] = field(default_factory=list)
    kdc_role: str = "kdc"
    trusts: list[str] = field(default_factory=list)
    principals: dict[str, PrincipalEntry] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "etypes": self.etypes,
            "max_ticket_lifetime": self.max_ticket_lifetime,
            "max_renewable_lifetime": self.max_renewable_lifetime,
            "domains": sorted(self.domains),
            "kdc_role": self.kdc_role,
            "trusts": sorted(self.trusts),
        }
        if self.principals:
            d["principals"] = {
                name: entry.to_dict()
                for name, entry in sorted(self.principals.items())
            }
        return d

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "RealmConfig":
        return cls(
            name=name,
            etypes=data.get("etypes", list(DEFAULT_ETYPES)),
            max_ticket_lifetime=data.get(
                "max_ticket_lifetime", DEFAULT_MAX_TICKET_LIFETIME),
            max_renewable_lifetime=data.get(
                "max_renewable_lifetime", DEFAULT_MAX_RENEWABLE_LIFETIME),
            domains=data.get("domains", []),
            kdc_role=data.get("kdc_role", "kdc"),
            trusts=data.get("trusts", []),
            principals={
                pname: PrincipalEntry.from_dict(pdata)
                for pname, pdata in data.get("principals", {}).items()
                if isinstance(pdata, dict)
            },
        )


def load(repo: SecretsRepo, realm: str) -> RealmConfig:
    """Load a realm's config, synthesising defaults if realm.toml is absent.

    Realms imported before realm.toml existed load with default etypes and no
    declared domains; ``aegis realm set`` fills those in.
    """
    config_path = repo.realm_config_path(realm)
    if not config_path.exists():
        return RealmConfig(name=realm)

    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    return RealmConfig.from_dict(realm, data)


def save(repo: SecretsRepo, config: RealmConfig) -> Path:
    """Write a realm's config."""
    config_path = repo.realm_config_path(config.name)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "wb") as f:
        tomli_w.dump(config.to_dict(), f)
    return config_path


# Principal naming ---------------------------------------------------------

def principal_filename(principal: str) -> str:
    """On-disk stem for a principal.

    Follows the convention established by the Ruby tooling: every ``/`` becomes
    ``_``.  ``host/foo.example.com`` -> ``host_foo.example.com``.

    Note this is not reversible for principals whose components contain an
    underscore, which is why ``realm.toml`` keeps the canonical name.
    """
    return principal.replace("/", "_")


def principal_from_filename(stem: str, index: dict[str, PrincipalEntry]) -> str:
    """Best-effort inverse of :func:`principal_filename`.

    Prefers the canonical name from the realm's principal index; falls back to
    splitting on the first underscore, which is correct for every principal
    shape currently in use (``service_fqdn``, ``krbtgt_REALM@REALM``).
    """
    for name in index:
        if principal_filename(name) == stem:
            return name
    if "_" in stem:
        service, rest = stem.split("_", 1)
        return f"{service}/{rest}"
    return stem


def stored_principals(repo: SecretsRepo, realm: str) -> list[str]:
    """Canonical names of every principal stored for a realm."""
    principals_dir = repo.realm_principals_path(realm)
    if not principals_dir.is_dir():
        return []
    config = load(repo, realm)
    return sorted(
        principal_from_filename(f.stem, config.principals)
        for f in principals_dir.glob("*.age")
    )


def previous_principals(repo: SecretsRepo, realm: str) -> list[str]:
    """Principals with a retained pre-rekey key, i.e. rotations in progress.

    Each one means some host may still be authenticating with the old key.
    They stay until `aegis realm rekey-principal --prune` drops them.
    """
    previous_dir = repo.realm_previous_principals_path(realm)
    if not previous_dir.is_dir():
        return []
    config = load(repo, realm)
    return sorted(
        principal_from_filename(f.stem, config.principals)
        for f in previous_dir.glob("*.age")
    )


def classify(principal: str, realm: str) -> PrincipalEntry:
    """Guess the kind of a principal from its name."""
    # Strip any realm suffix too: single-component principals look like
    # "default@REALM", with no slash to split on.
    service = principal.split("/", 1)[0].split("@", 1)[0]

    if service == "krbtgt":
        rest = principal.split("/", 1)[1] if "/" in principal else ""
        # krbtgt/REALM@REALM is the realm's own TGS; anything else is a trust.
        if "@" in rest:
            target, source = rest.split("@", 1)
            if target == realm and source == realm:
                return PrincipalEntry(kind=KIND_INFRASTRUCTURE)
            peer = source if target == realm else target
            return PrincipalEntry(kind=KIND_CROSS_REALM, peer=peer)
        return PrincipalEntry(kind=KIND_INFRASTRUCTURE)

    if service in ("kadmin", "changepw", "default", "WELLKNOWN"):
        return PrincipalEntry(kind=KIND_INFRASTRUCTURE)

    return PrincipalEntry(kind=KIND_SERVICE)


# Host / realm resolution --------------------------------------------------

def domains_of_host(repo: SecretsRepo, hostname: str) -> list[str]:
    """Domains a host belongs to, via its ``domain-<domain>`` role memberships."""
    domains = []
    for role_name in repo.list_roles():
        if not role_name.startswith(DOMAIN_ROLE_PREFIX):
            continue
        role_config = repo.get_role_config(role_name)
        if role_config and hostname in role_config.hosts:
            domains.append(role_name[len(DOMAIN_ROLE_PREFIX):])
    return sorted(domains)


def realm_of_domain(repo: SecretsRepo, domain: str) -> str | None:
    """The realm serving a domain, per each realm's declared ``domains``."""
    for realm_name in repo.list_realms():
        if domain in load(repo, realm_name).domains:
            return realm_name
    return None


@dataclass
class HostRealmMembership:
    hostname: str
    domain: str
    realm: str

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.domain}"


def memberships(repo: SecretsRepo) -> list[HostRealmMembership]:
    """Resolve every host to the realm(s) it belongs to.

    A host in two domains served by different realms yields two memberships,
    which is legitimate — it gets a principal in each.
    """
    # domain -> realm, computed once
    domain_realms: dict[str, str] = {}
    for realm_name in repo.list_realms():
        for domain in load(repo, realm_name).domains:
            domain_realms[domain] = realm_name

    result = []
    for hostname in repo.list_hosts():
        for domain in domains_of_host(repo, hostname):
            realm_name = domain_realms.get(domain)
            if realm_name:
                result.append(HostRealmMembership(hostname, domain, realm_name))
    return result


def hosts_by_realm(repo: SecretsRepo) -> dict[str, list[HostRealmMembership]]:
    """Group host memberships by realm."""
    grouped: dict[str, list[HostRealmMembership]] = {}
    for membership in memberships(repo):
        grouped.setdefault(membership.realm, []).append(membership)
    return grouped


def require_realm(repo: SecretsRepo, realm: str) -> RealmConfig:
    """Load a realm, failing if it does not exist on disk."""
    if not repo.realm_path(realm).is_dir():
        raise RealmError(
            f"Realm {realm} not found at {repo.realm_path(realm)}. "
            f"Create it with: aegis realm init {realm}"
        )
    return load(repo, realm)
