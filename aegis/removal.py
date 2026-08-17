"""Planning and applying deletions.

Every ``aegis <thing> delete`` has the same shape: work out what would be
removed, work out what still refers to it, show both, and stop if anything
does -- unless the operator overrides with ``--force``.

Refusing rather than cascading is deliberate.  A secrets repository is a graph:
a role is held by hosts, a host holds role keys, a Nebula network signs
certificates for both.  Cleaning up every edge automatically would make one
mistyped name remove a great deal, and the blast radius would only be visible
afterwards.  Naming what still points at the thing lets the operator decide
whether the reference or the entity is the mistake.

The planners are pure: they read the repo and describe the change, so a
``--dry-run`` and a real run see the same plan, and tests can assert on it
without a CliRunner.
"""

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config, host_secrets


@dataclass
class Edit:
    """A change to a declaration, as opposed to a file being removed."""
    description: str
    apply: Callable[[], None]


@dataclass
class Removal:
    """What deleting something would do, and what stands in the way."""

    kind: str
    name: str
    # Files and directories to delete, deepest interest first.
    paths: list[Path] = field(default_factory=list)
    # Declaration edits -- manifest and config rewrites.
    edits: list[Edit] = field(default_factory=list)
    # References that make this unsafe. Non-empty means refuse without --force.
    blockers: list[str] = field(default_factory=list)
    # Consequences worth stating even when nothing blocks.
    warnings: list[str] = field(default_factory=list)
    # What to run afterwards to bring generated output back into line.
    follow_up: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.paths and not self.edits


def apply(removal: Removal) -> None:
    """Carry out a planned removal.

    Edits run before deletions: a manifest rewrite reads files the deletions
    are about to remove, and doing it the other way round would have it read a
    half-deleted tree.
    """
    for edit in removal.edits:
        edit.apply()
    for path in removal.paths:
        _remove(path)


def _remove(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _existing(*paths: Path) -> list[Path]:
    """Keep only paths that are actually there, preserving order."""
    return [p for p in paths if p.is_symlink() or p.exists()]


def _age_count(path: Path) -> int:
    return len(list(path.rglob("*.age"))) if path.is_dir() else 0


def _drop_manifest_roles(repo: config.SecretsRepo, hostname: str, role: str) -> Edit:
    def do() -> None:
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        manifest.roles = [r for r in manifest.roles if r != role]
        host_secrets.save_host_manifest(repo.deploy_path, manifest)

    return Edit(f"{hostname}: drop '{role}' from the manifest roles list", do)


def _drop_manifest_secrets(
    repo: config.SecretsRepo, hostname: str, names: list[str]
) -> Edit:
    def do() -> None:
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        for name in names:
            manifest.secrets.pop(name, None)
        host_secrets.save_host_manifest(repo.deploy_path, manifest)

    listed = ", ".join(names)
    return Edit(f"{hostname}: drop [secrets] {listed} from the manifest", do)


def _drop_role_membership(repo: config.SecretsRepo, role: str, hostname: str) -> Edit:
    def do() -> None:
        role_config = repo.get_role_config(role)
        if role_config is None:
            return
        role_config.hosts = [h for h in role_config.hosts if h != hostname]
        repo.set_role_config(role_config)

    return Edit(f"role '{role}': drop {hostname} from its member list", do)


# =============================================================================
# Planners
# =============================================================================

def plan_host_removal(repo: config.SecretsRepo, hostname: str) -> Removal:
    """Delete a host: its declaration, its key and everything deployed to it."""
    removal = Removal("host", hostname)

    deploy = repo.host_deploy_path(hostname)
    removal.paths = _existing(
        repo.src_path / "hosts" / f"{hostname}.toml",
        deploy,
    )

    host_config = repo.get_host_config(hostname)
    status = host_config.status if host_config else config.STATUS_ACTIVE
    deployed = _age_count(deploy)

    # The repo's own preference is to retire rather than delete, and `check`
    # says so about leftover material. Deleting a live host's secrets removes
    # the record of what it held, which is exactly what you need in order to
    # know what to rotate.
    if status == config.STATUS_ACTIVE and deployed:
        removal.blockers.append(
            f"still active, with {deployed} encrypted file(s) deployed to it. "
            f"Retire it first so the rotation is recorded: "
            f"aegis host set-status {hostname} retired"
        )

    for role in repo.list_roles():
        role_config = repo.get_role_config(role)
        if role_config and hostname in role_config.hosts:
            removal.blockers.append(f"role '{role}' still lists it as a member")

    for username in repo.list_users():
        user_config = repo.get_user_config(username)
        if user_config and hostname in repo.resolve_user_allowed_hosts(user_config):
            removal.blockers.append(f"user '{username}' is allowed onto it")

    for network in repo.list_nebula_networks():
        if repo.nebula_host_config_path(network, hostname).exists():
            removal.blockers.append(f"Nebula network '{network}' has a config for it")

    if deployed:
        removal.warnings.append(
            f"{deployed} encrypted file(s) go with it. Whoever holds this "
            f"host's master key can still read any copy they already have, so "
            f"treat what it held as needing rotation."
        )

    return removal


def plan_role_removal(repo: config.SecretsRepo, role: str) -> Removal:
    """Delete a role: its key, its shared secrets and every member's copy."""
    removal = Removal("role", role)

    role_config = repo.get_role_config(role)
    members = list(role_config.hosts) if role_config else []

    removal.paths = _existing(
        repo.src_path / "roles" / f"{role}.toml",
        repo.role_key_path(role),
        repo.role_pubkey_path(role),
        repo.role_deploy_path(role),
        *[repo.host_role_key_path(host, role) for host in members],
    )

    for host in members:
        removal.edits.append(_drop_role_membership(repo, role, host))

    # A manifest entry pointing at a role secret is the reference that matters:
    # the aegis NixOS module fails evaluation on a role the host does not hold,
    # so leaving one behind breaks that host's build rather than just its
    # service.
    #
    # Grouped rather than one line per host: a role with two secrets and twelve
    # members is one decision, and twelve copies of it bury the rest of the
    # plan. Same reasoning as reencrypt's unresolvable grouping.
    pointing_hosts: list[str] = []
    pointing_names: set[str] = set()

    for host in repo.list_hosts():
        manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
        pointing = {
            name for name, entry in manifest.secrets.items() if entry.role == role
        }
        if pointing:
            pointing_hosts.append(host)
            pointing_names |= pointing
        if role in manifest.roles:
            removal.edits.append(_drop_manifest_roles(repo, host, role))

    if pointing_hosts:
        removal.blockers.append(
            f"{len(pointing_hosts)} host manifest(s) still declare "
            f"{', '.join(sorted(pointing_names))} as role secrets of '{role}': "
            f"{', '.join(pointing_hosts)}"
        )

    shared = repo.list_role_secrets(role)
    if shared:
        removal.warnings.append(
            f"{len(shared)} shared secret(s) go with it: {', '.join(shared)}. "
            f"They are encrypted to the admin set as well as to the role, so "
            f"recover any you still need before deleting."
        )

    removal.follow_up.append("aegis check")
    return removal


def plan_user_removal(repo: config.SecretsRepo, username: str) -> Removal:
    """Delete a user: their deployment key and every host's copy of it."""
    removal = Removal("user", username)

    removal.paths = _existing(
        repo.src_path / "users" / f"{username}.toml",
        repo.user_key_path(username),
        repo.user_pubkey_path(username),
        *[
            repo.host_deploy_path(host) / "users" / username
            for host in repo.list_hosts()
        ],
    )

    removal.warnings.append(
        "Their secrets are encrypted to this key. Anything only they could "
        "read becomes admin-only once it is gone."
    )
    return removal


def plan_secret_removal(
    repo: config.SecretsRepo,
    name: str,
    hosts: list[str],
    roles: list[str],
) -> Removal:
    """Delete one named secret from the hosts and/or roles that carry it."""
    removal = Removal("secret", name)

    # No selection means every recipient that actually has it -- deleting a
    # secret from one host and silently leaving it on three others is the
    # failure this avoids.
    if not hosts and not roles:
        hosts = [
            h for h in repo.list_hosts()
            if (repo.host_deploy_path(h) / "secrets" / f"{name}.age").exists()
        ]
        roles = [r for r in repo.list_roles() if name in repo.list_role_secrets(r)]

    removal.paths = _existing(
        *[repo.host_deploy_path(h) / "secrets" / f"{name}.age" for h in hosts],
        *[repo.role_secret_path(r, name) for r in roles],
    )

    for host in hosts:
        manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
        if name in manifest.secrets:
            removal.edits.append(_drop_manifest_secrets(repo, host, [name]))

    # A role secret is declared in every member's manifest, not the role's.
    for role in roles:
        role_config = repo.get_role_config(role)
        for host in (role_config.hosts if role_config else []):
            manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
            if name in manifest.secrets:
                removal.edits.append(_drop_manifest_secrets(repo, host, [name]))

    removal.warnings.append(
        "Any service still reading this path gets nothing at next boot. The "
        "value is not recoverable from this repo once the ciphertext is gone."
    )
    return removal


def plan_ssh_removal(repo: config.SecretsRepo, hostname: str) -> Removal:
    """Delete a host's SSH keys: its sshd identity, and the deploy/initrd pair."""
    removal = Removal("ssh keys", hostname)

    ssh_dir = repo.host_deploy_path(hostname) / "ssh"
    removal.paths = _existing(ssh_dir)

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    auxiliary = sorted(
        name for name, entry in manifest.secrets.items()
        if entry.source.startswith("ssh/")
    )

    def do() -> None:
        loaded = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        loaded.ssh_host_keys = []
        for name in auxiliary:
            loaded.secrets.pop(name, None)
        host_secrets.save_host_manifest(repo.deploy_path, loaded)

    if manifest.ssh_host_keys or auxiliary:
        removal.edits.append(
            Edit(f"{hostname}: drop ssh-host-keys and its ssh/ [secrets] entries", do)
        )

    removal.warnings.append(
        "This is the host's SSH identity. Every known_hosts entry and SSHFP "
        "record for it stops matching, and the next deploy mints a new one."
    )
    removal.follow_up.append(f"aegis build ssh-keys  # to mint a fresh identity")
    return removal


def plan_nexus_removal(repo: config.SecretsRepo, hostname: str) -> Removal:
    """Delete a host's Nexus HMAC key."""
    removal = Removal("nexus key", hostname)

    removal.paths = _existing(repo.host_deploy_path(hostname) / "nexus-key.age")

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)

    def do() -> None:
        loaded = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        loaded.nexus_key = None
        host_secrets.save_host_manifest(repo.deploy_path, loaded)

    if manifest.nexus_key is not None:
        removal.edits.append(Edit(f"{hostname}: drop the [nexus-key] entry", do))

    removal.warnings.append(
        "The Nexus server authenticates this host by the key's value, and its "
        "aggregate is built separately -- until that is rebuilt, the host's "
        "DNS updates are rejected rather than merely unsigned."
    )
    return removal


def plan_dnssec_removal(repo: config.SecretsRepo, domain: str) -> Removal:
    """Delete a domain's DNSSEC key signing key."""
    removal = Removal("dnssec", domain)

    removal.paths = _existing(
        repo.dnssec_src_path(domain),
        repo.dnssec_deploy_path(domain),
    )

    role = f"dns-master-{domain}"
    role_config = repo.get_role_config(role)
    if role_config and role_config.hosts:
        removal.blockers.append(
            f"role '{role}' still has {len(role_config.hosts)} member(s): "
            f"{', '.join(role_config.hosts)}"
        )

    removal.warnings.append(
        "A signed zone whose KSK is gone cannot be re-signed. Withdraw the DS "
        "record from the parent and let the old signatures expire first, or "
        "the zone goes bogus rather than merely unsigned."
    )
    return removal


def plan_nebula_network_removal(repo: config.SecretsRepo, network: str) -> Removal:
    """Delete a Nebula network: its CA, and every host's certificate."""
    removal = Removal("nebula network", network)

    hosts_dir = repo.nebula_hosts_path(network)
    members = (
        sorted(p.stem for p in hosts_dir.glob("*.toml")) if hosts_dir.is_dir() else []
    )

    removal.paths = _existing(
        repo.nebula_network_path(network),
        repo.nebula_deploy_path(network),
        *[repo.host_deploy_path(h) / "nebula" for h in members],
    )

    if members:
        removal.blockers.append(
            f"{len(members)} host(s) are still on it: {', '.join(members)}"
        )

    for host in repo.list_hosts():
        manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
        names = sorted(
            name for name in manifest.secrets if name.startswith(f"nebula-{network}-")
        )
        if names:
            removal.edits.append(_drop_manifest_secrets(repo, host, names))

    removal.warnings.append(
        "The CA private key goes with it, so no certificate for this network "
        "can ever be signed again and existing ones cannot be verified against "
        "a rebuilt CA."
    )
    return removal


def plan_nebula_host_removal(
    repo: config.SecretsRepo, network: str, hostname: str
) -> Removal:
    """Remove one host from a Nebula network."""
    removal = Removal("nebula host", f"{hostname} ({network})")

    removal.paths = _existing(
        repo.nebula_host_config_path(network, hostname),
        repo.nebula_host_pubkey_path(network, hostname),
        repo.host_deploy_path(hostname) / "nebula",
    )

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    names = sorted(
        name for name in manifest.secrets if name.startswith(f"nebula-{network}-")
    )
    if names:
        removal.edits.append(_drop_manifest_secrets(repo, hostname, names))

    removal.warnings.append(
        "Its certificate is not revoked, only undeployed -- it stays valid to "
        "every peer until it expires."
    )
    removal.follow_up.append("aegis build nebula  # rewrite network.json without it")
    return removal


def plan_realm_removal(repo: config.SecretsRepo, realm: str) -> Removal:
    """Delete a Kerberos realm: its master key and every principal."""
    removal = Removal("realm", realm)

    removal.paths = _existing(
        repo.realm_path(realm),
        repo.kdc_deploy_path() / realm,
    )

    principals_dir = repo.realm_principals_path(realm)
    principals = (
        len(list(principals_dir.glob("*.toml"))) if principals_dir.is_dir() else 0
    )
    if principals:
        removal.blockers.append(
            f"{principals} principal(s) are still declared in it"
        )

    removal.warnings.append(
        "Keytabs already built from this realm keep working until they are "
        "rebuilt, and nothing here can rebuild them afterwards -- every host "
        "in the realm loses its Kerberos identity at the next build."
    )
    return removal
