"""Who each encrypted file in the repo should be readable by.

One definition of the encryption policy, consumed by both ``aegis check``
(which compares it against what is on disk) and ``aegis reencrypt`` (which
rewrites files to match it).  Keeping them in step matters: a file that check
calls correct but reencrypt would rewrite differently is worse than no check
at all.

The admin set appears in every policy.  That is the whole recovery story: the
admin can decrypt anything, which is what makes re-encrypting for a *new*
admin key possible in the first place.

Files whose intended audience cannot be determined are reported rather than
guessed at.  age does not expose the recipients of an existing file, so
rewriting one means choosing a new recipient set blind — a wrong guess
silently destroys access.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config, realm as realm_mod

# Categories, roughly in order of how bad it is to lose access to them.
CAT_ADMIN_ONLY = "admin-only"
CAT_ROLE = "role"
CAT_HOST = "host"
CAT_USER = "user"
CAT_KDC = "kdc"
CAT_DNSSEC = "dnssec"
CAT_LEGACY = "legacy"


@dataclass
class FilePolicy:
    """The recipient set an encrypted file is expected to carry."""
    path: Path
    category: str
    recipients: list[str] = field(default_factory=list)
    label: str = ""
    #: Set when the intended recipients cannot be resolved; such a file is
    #: reported but never rewritten.
    problem: str | None = None

    @property
    def resolvable(self) -> bool:
        return self.problem is None and bool(self.recipients)

    @property
    def expected_count(self) -> int:
        return len(set(self.recipients))


class Resolver:
    """Caches the public keys needed to build recipient sets."""

    def __init__(self, repo: config.SecretsRepo, admin_keys: list[str]):
        self.repo = repo
        self.admin_keys = list(admin_keys)
        self._host: dict[str, str | None] = {}
        self._role: dict[str, str | None] = {}
        self._user: dict[str, str | None] = {}
        self._host_kdc: dict[str, str | None] | None = None
        self._realm_kdc: dict[str, str | None] | None = None

    def host(self, hostname: str) -> str | None:
        if hostname not in self._host:
            host_config = self.repo.get_host_config(hostname)
            self._host[hostname] = host_config.age_pubkey if host_config else None
        return self._host[hostname]

    def role(self, role_name: str) -> str | None:
        if role_name not in self._role:
            path = self.repo.role_pubkey_path(role_name)
            self._role[role_name] = (
                path.read_text().strip() if path.exists() else None)
        return self._role[role_name]

    def user(self, username: str) -> str | None:
        if username not in self._user:
            user_config = self.repo.get_user_config(username)
            key = user_config.public_key if user_config else None
            if not key:
                path = self.repo.user_pubkey_path(username)
                key = path.read_text().strip() if path.exists() else None
            self._user[username] = key
        return self._user[username]

    def _build_kdc_maps(self) -> None:
        self._realm_kdc = {}
        self._host_kdc = {}
        for realm_name in self.repo.list_realms():
            realm_config = realm_mod.load(self.repo, realm_name)
            self._realm_kdc[realm_name] = self.role(realm_config.kdc_role)
        for membership in realm_mod.memberships(self.repo):
            key = self._realm_kdc.get(membership.realm)
            if key:
                self._host_kdc[membership.hostname] = key

    def kdc_for_host(self, hostname: str) -> str | None:
        if self._host_kdc is None:
            self._build_kdc_maps()
        assert self._host_kdc is not None
        return self._host_kdc.get(hostname)

    def kdc_for_realm(self, realm_name: str) -> str | None:
        if self._realm_kdc is None:
            self._build_kdc_maps()
        assert self._realm_kdc is not None
        return self._realm_kdc.get(realm_name)


def _admin_label(n: int) -> str:
    return f"{n} admin key{'s' if n != 1 else ''}"


def _admin_only(path: Path, resolver: Resolver, what: str) -> FilePolicy:
    return FilePolicy(
        path=path,
        category=CAT_ADMIN_ONLY,
        recipients=list(resolver.admin_keys),
        label=f"{what}: {_admin_label(len(resolver.admin_keys))}",
    )


def _with_host(
    path: Path,
    resolver: Resolver,
    hostname: str,
    category: str,
    extra: list[str] | None = None,
    extra_label: str = "",
) -> FilePolicy:
    host_key = resolver.host(hostname)
    if host_key is None:
        return FilePolicy(
            path=path,
            category=category,
            problem=f"host {hostname} has no master key configured",
        )
    recipients = [host_key, *resolver.admin_keys, *(extra or [])]
    label = f"host({hostname}) + {_admin_label(len(resolver.admin_keys))}"
    if extra_label:
        label += f" + {extra_label}"
    return FilePolicy(path=path, category=category, recipients=recipients, label=label)


def _host_files(repo: config.SecretsRepo, resolver: Resolver) -> list[FilePolicy]:
    policies: list[FilePolicy] = []

    for hostname in repo.list_deployed_hosts():
        deploy = repo.host_deploy_path(hostname)

        for path in sorted(deploy.rglob("*.age")):
            relative = path.relative_to(deploy)
            head = relative.parts[0]

            if head == "roles":
                # A host's copy of a role private key: readable by that host so
                # it can use the role, and by the admin so the copy can be
                # regenerated.
                policies.append(
                    _with_host(path, resolver, hostname, CAT_ROLE))

            elif head == "users":
                username = relative.parts[1] if len(relative.parts) > 2 else None
                if username is None:
                    policies.append(FilePolicy(
                        path=path, category=CAT_USER,
                        problem="unrecognised layout under users/"))
                elif path.name == "manifest.age":
                    # The manifest maps hashed filenames back to real names;
                    # the user gets it so they can audit what is deployed.
                    user_key = resolver.user(username)
                    policies.append(_with_host(
                        path, resolver, hostname, CAT_USER,
                        extra=[user_key] if user_key else None,
                        extra_label=f"user({username})" if user_key else "",
                    ))
                else:
                    policies.append(
                        _with_host(path, resolver, hostname, CAT_USER))

            elif path.name == "keytab.age":
                kdc_key = resolver.kdc_for_host(hostname)
                if kdc_key is None:
                    policies.append(FilePolicy(
                        path=path, category=CAT_HOST,
                        problem=(
                            f"no KDC role public key for {hostname}'s realm; "
                            f"cannot tell who should read this keytab"),
                    ))
                else:
                    policies.append(_with_host(
                        path, resolver, hostname, CAT_HOST,
                        extra=[kdc_key], extra_label="KDC role"))

            else:
                policies.append(
                    _with_host(path, resolver, hostname, CAT_HOST))

    return policies


def _admin_only_files(
    repo: config.SecretsRepo, resolver: Resolver
) -> list[FilePolicy]:
    """Material encrypted for the admin set and nobody else.

    This is what makes a lost admin key catastrophic: role private keys, user
    private keys, realm master keys and every Kerberos principal live here.
    Hosts keep running without it, but nothing can ever be added to a realm or
    a role again.
    """
    policies: list[FilePolicy] = []

    roles_dir = repo.keys_path / "roles"
    if roles_dir.is_dir():
        for path in sorted(roles_dir.glob("*.age")):
            policies.append(_admin_only(path, resolver, "role private key"))

    users_dir = repo.keys_path / "users"
    if users_dir.is_dir():
        for path in sorted(users_dir.glob("*.age")):
            policies.append(_admin_only(path, resolver, "user private key"))

    for realm_name in repo.list_realms():
        key_path = repo.realm_key_path(realm_name)
        if key_path.exists():
            policies.append(
                _admin_only(key_path, resolver, f"{realm_name} realm master key"))

        principals = repo.realm_principals_path(realm_name)
        if principals.is_dir():
            for path in sorted(principals.glob("*.age")):
                policies.append(
                    _admin_only(path, resolver, f"{realm_name} principal"))

    return policies


def _kdc_files(repo: config.SecretsRepo, resolver: Resolver) -> list[FilePolicy]:
    kdc_dir = repo.kdc_deploy_path()
    if not kdc_dir.is_dir():
        return []

    policies = []
    for path in sorted(kdc_dir.glob("*.age")):
        # <REALM>-principals.age / <REALM>-realm-key.age
        stem = path.stem
        realm_name = None
        for suffix in ("-principals", "-realm-key"):
            if stem.endswith(suffix):
                realm_name = stem[: -len(suffix)]
                break

        if realm_name is None:
            policies.append(FilePolicy(
                path=path, category=CAT_KDC,
                problem="cannot tell which realm this bundle belongs to"))
            continue

        kdc_key = resolver.kdc_for_realm(realm_name)
        if kdc_key is None:
            policies.append(FilePolicy(
                path=path, category=CAT_KDC,
                problem=f"no KDC role public key for realm {realm_name}"))
            continue

        policies.append(FilePolicy(
            path=path,
            category=CAT_KDC,
            recipients=[kdc_key, *resolver.admin_keys],
            label=f"KDC role({realm_name}) + {_admin_label(len(resolver.admin_keys))}",
        ))

    return policies


def _dnssec_files(repo: config.SecretsRepo, resolver: Resolver) -> list[FilePolicy]:
    dnssec_dir = repo.deploy_path / "dnssec"
    if not dnssec_dir.is_dir():
        return []

    policies = []
    for domain in repo.list_dnssec_domains():
        domain_dir = repo.dnssec_deploy_path(domain)
        if not domain_dir.is_dir():
            continue
        role_name = f"dns-master-{domain}"
        role_key = resolver.role(role_name)
        for path in sorted(domain_dir.glob("*.age")):
            if role_key is None:
                policies.append(FilePolicy(
                    path=path, category=CAT_DNSSEC,
                    problem=f"role {role_name} has no public key"))
            else:
                policies.append(FilePolicy(
                    path=path,
                    category=CAT_DNSSEC,
                    recipients=[role_key, *resolver.admin_keys],
                    label=f"role({role_name}) + {_admin_label(len(resolver.admin_keys))}",
                ))
    return policies


def _legacy_files(repo: config.SecretsRepo, claimed: set[Path]) -> list[FilePolicy]:
    """Encrypted files under deploy/ that no current policy accounts for.

    deploy/domains/ predates the dnssec/ and roles/ layouts and nothing writes
    it any more. Its recipient sets cannot be recovered from the files
    themselves, so these are reported and left alone rather than rewritten to
    a guess.
    """
    policies = []
    if not repo.deploy_path.is_dir():
        return policies

    for path in sorted(repo.deploy_path.rglob("*.age")):
        if path in claimed:
            continue
        policies.append(FilePolicy(
            path=path,
            category=CAT_LEGACY,
            problem=(
                "no current policy describes this file; its recipients cannot "
                "be recovered, so it is left untouched"),
        ))
    return policies


def plan(repo: config.SecretsRepo, admin_keys: list[str]) -> list[FilePolicy]:
    """Every encrypted file in the repo, with the recipients it should carry."""
    resolver = Resolver(repo, admin_keys)

    policies = (
        _admin_only_files(repo, resolver)
        + _host_files(repo, resolver)
        + _kdc_files(repo, resolver)
        + _dnssec_files(repo, resolver)
    )

    claimed = {p.path for p in policies}
    policies += _legacy_files(repo, claimed)

    return policies


def by_category(policies: list[FilePolicy]) -> dict[str, list[FilePolicy]]:
    grouped: dict[str, list[FilePolicy]] = {}
    for policy in policies:
        grouped.setdefault(policy.category, []).append(policy)
    return grouped
