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
class KeytabSpec:
    """A named keytab: which principals go in it, and who receives it.

    The host keytab built for every realm member is implicit and holds
    ``<service>/<fqdn>`` for that host alone.  A named keytab is the explicit
    form: an arbitrary principal list, delivered to whoever is declared here.

    Three delivery modes, and the absence of the first two is meaningful:

    ``hosts``
        One ciphertext per host, encrypted to that host's master key.
    ``roles``
        One ciphertext per role, encrypted to the role key and decrypted in
        phase 2 by every member -- so the keytab follows the service between
        machines without being rebuilt.
    neither
        Export-only.  The keytab is built and stored encrypted to the admin
        set, and reaches its consumer through ``aegis keytab export``.  This
        is the mode for anything Aegis does not deploy to: a Kubernetes
        secret, an appliance, a host someone else manages.  Aegis still owns
        the principals, so the keytab exists, is rebuilt on rekey, and is
        accounted for by ``check`` -- it just does not travel by itself.
    """
    principals: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def export_only(self) -> bool:
        """Whether this keytab has no in-band delivery target."""
        return not self.hosts and not self.roles

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"principals": sorted(self.principals)}
        if self.hosts:
            d["hosts"] = sorted(self.hosts)
        if self.roles:
            d["roles"] = sorted(self.roles)
        if self.note:
            d["note"] = self.note
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "KeytabSpec":
        return cls(
            principals=data.get("principals", []),
            hosts=data.get("hosts", []),
            roles=data.get("roles", []),
            note=data.get("note", ""),
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
    keytabs: dict[str, KeytabSpec] = field(default_factory=dict)

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
        if self.keytabs:
            d["keytabs"] = {
                name: spec.to_dict()
                for name, spec in sorted(self.keytabs.items())
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
            keytabs={
                kname: KeytabSpec.from_dict(kdata)
                for kname, kdata in data.get("keytabs", {}).items()
                if isinstance(kdata, dict)
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


# Named keytabs ------------------------------------------------------------
#
# A keytab is declared on the realm whose principals it holds: the realm
# already carries the principal index, so "does this keytab name something
# that exists" is answerable in one place.  Names are global rather than
# per-realm, because delivery is not: a host manifest has one flat [keytabs]
# table, and two realms declaring `hermes` would collide there with no way to
# tell which one a host meant.  `aegis keytab new` and `aegis check` enforce
# it; `find_keytab` reports the collision rather than picking a winner.

@dataclass
class KeytabRef:
    """A named keytab together with the realm that declares it."""
    name: str
    realm: str
    spec: KeytabSpec


def all_keytabs(repo: SecretsRepo) -> list[KeytabRef]:
    """Every named keytab in the repo, across all realms."""
    refs = []
    for realm_name in repo.list_realms():
        for name, spec in load(repo, realm_name).keytabs.items():
            refs.append(KeytabRef(name=name, realm=realm_name, spec=spec))
    return sorted(refs, key=lambda r: (r.name, r.realm))


def duplicate_keytab_names(repo: SecretsRepo) -> dict[str, list[str]]:
    """Keytab names declared by more than one realm, mapped to those realms."""
    seen: dict[str, list[str]] = {}
    for ref in all_keytabs(repo):
        seen.setdefault(ref.name, []).append(ref.realm)
    return {name: realms for name, realms in seen.items() if len(realms) > 1}


def find_keytab(repo: SecretsRepo, name: str) -> KeytabRef:
    """Look up a keytab by name.

    Raises rather than guessing when the name is ambiguous: two realms
    claiming it means the repo is already broken, and silently choosing one
    would build a keytab from the wrong realm's principals.
    """
    matches = [ref for ref in all_keytabs(repo) if ref.name == name]
    if not matches:
        raise RealmError(
            f"No keytab named {name!r}. "
            f"Create it with: aegis keytab new {name} --realm <REALM>"
        )
    if len(matches) > 1:
        realms = ", ".join(ref.realm for ref in matches)
        raise RealmError(
            f"Keytab {name!r} is declared by more than one realm ({realms}). "
            f"Keytab names must be unique across realms; rename one with "
            f"'aegis keytab delete' and 'aegis keytab new'."
        )
    return matches[0]


def keytabs_for_host(repo: SecretsRepo, hostname: str) -> list[KeytabRef]:
    """Named keytabs delivered to a host as its own per-host copy."""
    return [ref for ref in all_keytabs(repo) if hostname in ref.spec.hosts]


def keytabs_for_role(repo: SecretsRepo, role_name: str) -> list[KeytabRef]:
    """Named keytabs delivered to a role as one shared copy."""
    return [ref for ref in all_keytabs(repo) if role_name in ref.spec.roles]
