"""``aegis check`` and ``aegis reencrypt`` — reconcile src/ against deploy/.

Every build step in aegis is "create if missing", never "reconcile".  That
makes ordering silently load-bearing: build a keytab before the KDC role
exists and it is encrypted without the KDC as a recipient, forever, because
re-running skips the file that already exists.

``check`` reports drift without changing anything.  ``reencrypt`` repairs the
kind of drift that is about *recipients* rather than key material, so it is
always safe to run.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import typer

from . import (
    admin, config, crypto, host_secrets, realm as realm_mod, recipients,
)
from .errors import AegisError

SEVERITY_ERROR = "error"
SEVERITY_WARN = "warn"
#: Neither wrong nor suspicious -- state worth stating.  A host that is
#: deliberately not managed should appear in the output, or its absence reads
#: as an oversight; but it must not count towards the exit status, or the
#: check becomes something you learn to ignore.
SEVERITY_INFO = "info"


@dataclass
class Finding:
    severity: str
    scope: str
    message: str
    hint: str | None = None


class Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def error(self, scope: str, message: str, hint: str | None = None) -> None:
        self.findings.append(Finding(SEVERITY_ERROR, scope, message, hint))

    def warn(self, scope: str, message: str, hint: str | None = None) -> None:
        self.findings.append(Finding(SEVERITY_WARN, scope, message, hint))

    def info(self, scope: str, message: str, hint: str | None = None) -> None:
        self.findings.append(Finding(SEVERITY_INFO, scope, message, hint))

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_WARN]

    @property
    def notes(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_INFO]


def _check_admin(repo: config.SecretsRepo, report: Report) -> list[str]:
    """Validate the admin recipient set; returns it (possibly empty)."""
    try:
        keys = admin.recipients(repo)
    except AegisError as e:
        report.error("admin", str(e))
        return []

    if len(keys) == 1:
        report.warn(
            "admin",
            "only one admin key is registered, so losing it makes every role "
            "key, user key and Kerberos realm unrecoverable",
            "register an offline backup: aegis admin add-key --name backup",
        )

    try:
        admin.validate_local_key(repo)
    except AegisError as e:
        report.error("admin", str(e).splitlines()[0], "aegis admin list-keys")

    return keys


def _check_layout(repo: config.SecretsRepo, report: Report) -> None:
    if repo.uses_legacy_deploy_dir():
        report.warn(
            "layout",
            f"output directory is still named '{repo.deploy_path.name}/', which "
            f"reads as a regenerable artifact but holds the only copy of SSH "
            f"host keys, Nexus keys and DNSSEC private keys",
            "rename it to deploy/ (git mv build deploy)",
        )

    if repo.legacy_admin_key_path().exists() and repo.admin_keys_path().is_dir():
        if any(repo.admin_keys_path().glob("*.pub")):
            report.warn(
                "admin",
                f"both {repo.legacy_admin_key_path()} and {repo.admin_keys_path()} "
                f"exist; the directory wins and the loose file is ignored",
                "aegis admin migrate",
            )


def _check_hosts(
    repo: config.SecretsRepo,
    report: Report,
    admin_keys: list[str],
) -> None:
    configured = set(repo.list_hosts())

    for hostname in sorted(configured):
        host_config = repo.get_host_config(hostname)
        scope = f"host/{hostname}"

        status = host_config.status if host_config else config.STATUS_ACTIVE
        if status != config.STATUS_ACTIVE:
            # Not a host Aegis delivers to, so it is not missing anything.
            # What *would* be wrong is leftover deployed material: a host that
            # is gone or never arrived should hold nothing.
            deploy = repo.host_deploy_path(hostname)
            stale = sorted(deploy.rglob("*.age")) if deploy.is_dir() else []
            if stale:
                report.error(
                    scope,
                    f"status is {status} but {len(stale)} encrypted file(s) are "
                    f"still deployed to it"
                    + (", and its key can still read them"
                       if status == config.STATUS_RETIRED else ""),
                    f"rm -r {deploy}"
                    + (" && rotate whatever it held"
                       if status == config.STATUS_RETIRED else ""),
                )
            else:
                note = f" ({host_config.note})" if host_config and host_config.note else ""
                report.info(scope, f"{status}, skipped{note}")
            continue

        if not host_config or not host_config.age_pubkey:
            report.error(
                scope,
                "no master key set",
                f"aegis host set-key {hostname} --public-key 'age1...', or "
                f"record why it has none: aegis host set-status {hostname} pending",
            )
            continue

        deploy = repo.host_deploy_path(hostname)
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)

        ssh_dir = deploy / "ssh"
        ssh_files = sorted(ssh_dir.glob("*.age")) if ssh_dir.is_dir() else []
        if ssh_files and not manifest.ssh_host_keys:
            report.error(
                scope,
                f"{len(ssh_files)} SSH key files exist but the manifest has no "
                f"ssh-host-keys section, so NixOS will not deploy them",
                "aegis reencrypt --host " + hostname,
            )
        if manifest.ssh_host_keys and not ssh_files:
            report.error(
                scope, "manifest declares SSH host keys but no key files exist")

        keytab = deploy / "keytab.age"
        if keytab.exists() and manifest.keytab is None:
            report.error(
                scope,
                "keytab.age exists but the manifest has no keytab entry",
                "aegis reencrypt --host " + hostname,
            )

        if (deploy / "nexus-key.age").exists() and manifest.nexus_key is None:
            report.error(
                scope,
                "nexus-key.age exists but the manifest has no nexus-key entry",
                "aegis reencrypt --host " + hostname,
            )

        # Manifest must agree with declared placement, or a change to src/
        # silently never reaches the host.
        _check_placement_drift(repo, hostname, host_config, manifest, report, scope)

        roles_dir = deploy / "roles"
        role_files = (
            {f.stem for f in roles_dir.glob("*.age")} if roles_dir.is_dir() else set()
        )
        if sorted(role_files) != sorted(manifest.roles):
            report.warn(
                scope,
                f"manifest roles {manifest.roles or '[]'} do not match role key "
                f"files {sorted(role_files) or '[]'}",
                "aegis build role-keys",
            )

    for hostname in repo.list_deployed_hosts():
        if hostname not in configured:
            deploy = repo.host_deploy_path(hostname)
            count = sum(1 for _ in deploy.rglob("*") if _.is_file())
            report.error(
                f"host/{hostname}",
                f"has output in {repo.deploy_path.name}/ but no config in src/hosts/ "
                f"({count} files)",
                f"remove it, or re-add with: aegis host add {hostname}",
            )


def _check_placement_drift(
    repo: config.SecretsRepo,
    hostname: str,
    host_config: config.HostConfig,
    manifest: host_secrets.HostSecretsManifest,
    report: Report,
    scope: str,
) -> None:
    """Flag manifest entries that disagree with src/ placement."""
    expected_keytab = host_secrets.make_keytab_entry(
        host_config.placement_for("keytab"))
    if manifest.keytab and manifest.keytab.target != expected_keytab.target:
        report.warn(
            scope,
            f"keytab target in manifest ({manifest.keytab.target}) differs from "
            f"src/ placement ({expected_keytab.target})",
            f"aegis reencrypt --host {hostname}",
        )

    expected_nexus = host_secrets.make_nexus_key_entry(
        host_config.placement_for("nexus-key"))
    if manifest.nexus_key and manifest.nexus_key.target != expected_nexus.target:
        report.warn(
            scope,
            f"nexus-key target in manifest ({manifest.nexus_key.target}) differs "
            f"from src/ placement ({expected_nexus.target})",
            f"aegis reencrypt --host {hostname}",
        )

    declared_dir = host_config.placement_for("ssh-host-keys").target_dir
    if declared_dir:
        for entry in manifest.ssh_host_keys:
            if entry.target_dir != declared_dir:
                report.warn(
                    scope,
                    f"SSH key target_dir in manifest ({entry.target_dir}) differs "
                    f"from src/ placement ({declared_dir})",
                    f"aegis reencrypt --host {hostname}",
                )
                break


def _check_roles(repo: config.SecretsRepo, report: Report) -> None:
    configured_hosts = set(repo.list_hosts())

    for role_name in repo.list_roles():
        role_config = repo.get_role_config(role_name)
        if role_config is None:
            continue

        scope = f"role/{role_name}"

        if not repo.role_key_path(role_name).exists():
            report.error(
                scope,
                "no master key in keys/roles/, so no host can be added to it",
                f"aegis role init {role_name}",
            )
        if not repo.role_pubkey_path(role_name).exists():
            report.error(
                scope,
                "no public key, so nothing can be encrypted to this role",
                f"aegis role init {role_name}",
            )

        missing = [
            hostname for hostname in role_config.hosts
            if not repo.host_role_key_path(hostname, role_name).exists()
        ]
        if missing:
            report.error(
                scope,
                f"{len(role_config.hosts)} members, {len(missing)} without a key "
                f"file: {', '.join(sorted(missing))}",
                "aegis build role-keys",
            )

        unknown = [h for h in role_config.hosts if h not in configured_hosts]
        if unknown:
            report.warn(
                scope,
                f"members not configured in src/hosts/: {', '.join(sorted(unknown))}")

        _check_role_secrets(repo, report, role_config, scope)

    # Files in the roles output directory that no role in src/ accounts for.
    # These accumulate when a role is renamed: the new name gets a config, the
    # old one's key material is left behind and still decrypts whatever it was
    # encrypted for.
    roles_dir = repo.roles_deploy_path()
    if roles_dir.is_dir():
        configured_roles = set(repo.list_roles())
        for path in sorted(roles_dir.iterdir()):
            # A role's secrets live in a directory beside its public key; those
            # are checked per role above, not by extension here.
            if path.is_dir():
                if path.name not in configured_roles:
                    report.warn(
                        "roles",
                        f"{path.name}/ holds secrets for a role with no config "
                        f"in src/roles/ (orphaned by a rename?)",
                        f"remove it, or recreate the role: aegis role init {path.name}",
                    )
                continue
            if path.suffix not in (".age", ".pub"):
                continue
            if path.stem not in configured_roles:
                report.warn(
                    "roles",
                    f"{path.name} has no matching config in src/roles/ "
                    f"(orphaned by a rename?)",
                    f"remove it, or recreate the role: aegis role init {path.stem}",
                )

    # Role key files for hosts that are no longer members: removal deletes the
    # file, so a leftover means something went wrong (or was hand-edited).
    for hostname in repo.list_deployed_hosts():
        roles_dir = repo.host_deploy_path(hostname) / "roles"
        if not roles_dir.is_dir():
            continue
        for key_file in sorted(roles_dir.glob("*.age")):
            role_config = repo.get_role_config(key_file.stem)
            if role_config is None:
                report.warn(
                    f"host/{hostname}",
                    f"holds a key for role '{key_file.stem}', which no longer exists",
                    f"rm {key_file}",
                )
            elif hostname not in role_config.hosts:
                report.error(
                    f"host/{hostname}",
                    f"holds a key for role '{key_file.stem}' but is not a member",
                    f"aegis role remove-host {key_file.stem} {hostname}",
                )


def _check_role_secrets(
    repo: config.SecretsRepo,
    report: Report,
    role_config: config.RoleConfig,
    scope: str,
) -> None:
    """Whether a role's secrets actually reach the hosts that should have them.

    A role secret is one file that every member's manifest points at, so the
    failure mode is not a missing ciphertext but a manifest that was never
    regenerated: the secret exists, the host is a member, and nothing deploys
    it.  Nothing here reads plaintext -- only who declares what.
    """
    role_name = role_config.name
    secret_names = repo.list_role_secrets(role_name)

    if not secret_names:
        # Placement recorded for a secret that was never imported: harmless,
        # but it usually means a typo in the name.
        for kind in sorted(role_config.placement):
            report.warn(
                scope,
                f"placement recorded for {kind}, but the role holds no such secret",
                f"aegis role set-placement {role_name} {kind} --clear",
            )
        return

    if not role_config.hosts:
        report.warn(
            scope,
            f"holds {len(secret_names)} secret(s) but has no members, so "
            f"nothing deploys them: {', '.join(secret_names)}",
            f"aegis role add-host {role_name} <host>",
        )
        return

    deploying = set(repo.list_deploying_hosts())
    stale: list[str] = []

    for hostname in role_config.hosts:
        if hostname not in deploying:
            continue
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        declared = {
            name for name, entry in manifest.secrets.items()
            if entry.role == role_name
        }
        shadowed = {
            name for name, entry in manifest.secrets.items()
            if not entry.role and name in secret_names
        }
        if shadowed:
            report.warn(
                f"host/{hostname}",
                f"has its own secret(s) named {', '.join(sorted(shadowed))}, "
                f"shadowing the same name(s) from role '{role_name}'",
                "rename one of them, or drop the host's copy",
            )
        if set(secret_names) - declared - shadowed:
            stale.append(hostname)

    if stale:
        report.error(
            scope,
            f"{len(stale)} member(s) whose manifest does not declare every "
            f"role secret: {', '.join(sorted(stale))}",
            "aegis build role-secrets",
        )


def _check_realms(repo: config.SecretsRepo, report: Report) -> None:
    realms = repo.list_realms()
    if not realms:
        return

    grouped = realm_mod.hosts_by_realm(repo)

    for realm_name in realms:
        realm_config = realm_mod.load(repo, realm_name)
        scope = f"realm/{realm_name}"

        if not repo.realm_config_path(realm_name).exists():
            report.warn(
                scope,
                "no realm.toml, so etypes and lifetimes fall back to defaults "
                "that may not match how the realm was created",
                f"aegis realm set {realm_name} --add-domain <domain>",
            )

        # A retained pre-rekey key means a rotation was started and never
        # finished. Keytabs still carry the old key, so anything holding an
        # un-redeployed keytab keeps working -- but the old key stays valid
        # until it is pruned, which is not what a rotation is for.
        pending = realm_mod.previous_principals(repo, realm_name)
        if pending:
            shown = ", ".join(pending[:4]) + (
                f" (+{len(pending) - 4} more)" if len(pending) > 4 else "")
            report.warn(
                scope,
                f"{len(pending)} principal(s) mid-rotation, still carrying a "
                f"pre-rekey key: {shown}",
                f"redeploy the affected hosts, then: aegis realm "
                f"rekey-principal {realm_name} <principal> --prune",
            )

        if not realm_config.domains:
            report.error(
                scope,
                "no domains declared, so no host resolves to this realm and "
                "no keytabs will be built",
                f"aegis realm set {realm_name} --add-domain <domain>",
            )
            continue

        members = grouped.get(realm_name, [])
        if not members:
            report.warn(
                scope,
                f"serves {', '.join(realm_config.domains)} but no host is a member "
                f"of the corresponding domain-* roles",
            )
            continue

        kdc_pub = repo.role_pubkey_path(realm_config.kdc_role)
        if not kdc_pub.exists():
            report.error(
                scope,
                f"KDC role '{realm_config.kdc_role}' has no public key; keytabs "
                f"built now will not be readable by the KDC",
                f"aegis role init {realm_config.kdc_role}",
            )

        without_keytab = [
            m.hostname for m in members
            if not (repo.host_deploy_path(m.hostname) / "keytab.age").exists()
        ]
        if without_keytab:
            report.warn(
                scope,
                f"{len(members)} hosts in realm, {len(without_keytab)} without a "
                f"keytab: {', '.join(sorted(without_keytab)[:5])}"
                + (" ..." if len(without_keytab) > 5 else ""),
                "aegis build keytabs",
            )

        bundle = repo.kdc_deploy_path() / f"{realm_name}-principals.age"
        if kdc_pub.exists() and not bundle.exists():
            report.warn(
                scope,
                "no KDC principal bundle has been exported",
                f"aegis realm export {realm_name}",
            )

        for peer in realm_config.trusts:
            principal = f"krbtgt/{peer}@{realm_name}"
            stem = realm_mod.principal_filename(principal)
            if not (repo.realm_principals_path(realm_name) / f"{stem}.age").exists():
                report.error(
                    scope,
                    f"declares trust with {peer} but {principal} is not stored",
                    f"aegis realm trust {realm_name} {peer}",
                )


def _check_users(repo: config.SecretsRepo, report: Report) -> None:
    for username in repo.list_users():
        user_config = repo.get_user_config(username)
        if user_config is None:
            continue

        scope = f"user/{username}"
        allowed = repo.resolve_user_allowed_hosts(user_config)

        if not repo.user_key_path(username).exists():
            report.error(
                scope,
                "no private key in keys/users/, so their repo cannot be decrypted",
                f"aegis user add {username} --hosts=...",
            )

        for hostname in repo.list_deployed_hosts():
            user_dir = repo.host_deploy_path(hostname) / "users" / username
            if not user_dir.is_dir():
                continue
            if hostname not in allowed:
                count = sum(1 for _ in user_dir.rglob("*") if _.is_file())
                report.error(
                    scope,
                    f"still has {count} files on {hostname}, which is not in their "
                    f"host list -- removing access does not delete deployed secrets",
                    f"rm -r {user_dir}",
                )


def _check_recipients(
    repo: config.SecretsRepo,
    report: Report,
    admin_keys: list[str],
) -> None:
    """Spot files missing a recipient they should have.

    age does not reveal *which* keys a file was encrypted to, but the number
    of recipient stanzas is visible, and a count below the expected minimum is
    conclusive: something was encrypted before the recipient set grew.

    Everything encrypted in the repo is covered, not just per-host output.
    The admin-only material -- role private keys, user private keys, realm
    master keys, every Kerberos principal -- is exactly what a lost admin key
    makes unrecoverable, so it is the most important thing to keep in step
    with the admin set.
    """
    if not admin_keys:
        return

    policies = recipients.plan(repo, admin_keys)
    shortfalls: dict[str, list[str]] = {}

    for policy in policies:
        rel = _relative(repo, policy.path)

        if policy.problem:
            # Legacy files are reported once, in aggregate, further down.
            if policy.category != recipients.CAT_LEGACY:
                report.warn(
                    f"recipients/{policy.category}",
                    f"{rel}: {policy.problem}",
                )
            continue

        found = crypto.recipients_of(policy.path)
        if found and found < policy.expected_count:
            shortfalls.setdefault(policy.category, []).append(
                f"{rel} ({found} of {policy.expected_count}: {policy.label})")

    for category, entries in sorted(shortfalls.items()):
        shown = entries[:4]
        more = len(entries) - len(shown)
        detail = "; ".join(shown) + (f"; +{more} more" if more > 0 else "")
        hint = (
            "aegis reencrypt"
            if category != recipients.CAT_HOST
            else "aegis reencrypt --host <host>"
        )
        report.error(
            f"recipients/{category}",
            f"{len(entries)} file(s) missing a recipient: {detail}",
            hint,
        )

    legacy = [p for p in policies if p.category == recipients.CAT_LEGACY]
    if legacy:
        # Group by subtree: "245 unknown files" is not actionable, but
        # "deploy/realms: 175" points straight at what to investigate.
        subtrees: dict[str, int] = {}
        for policy in legacy:
            parts = policy.path.relative_to(repo.deploy_path).parts
            subtrees[parts[0]] = subtrees.get(parts[0], 0) + 1

        detail = ", ".join(
            f"{name}/ ({count})"
            for name, count in sorted(subtrees.items(), key=lambda kv: -kv[1])
        )
        report.warn(
            "recipients/legacy",
            f"{len(legacy)} encrypted file(s) under {repo.deploy_path.name}/ that no "
            f"current policy describes: {detail}. reencrypt leaves them alone, so a "
            f"new admin key will not reach them",
            "confirm what they are, then regenerate or delete them",
        )


def _relative(repo: config.SecretsRepo, path: Path) -> str:
    try:
        return str(path.relative_to(repo.path))
    except ValueError:
        return str(path)


@dataclass
class CheckResult:
    report: Report


def run_check(repo: config.SecretsRepo) -> Report:
    """Collect every consistency finding for a repo."""
    report = Report()
    _check_layout(repo, report)
    admin_keys = _check_admin(repo, report)
    _check_hosts(repo, report, admin_keys)
    _check_roles(repo, report)
    _check_realms(repo, report)
    _check_users(repo, report)
    _check_recipients(repo, report, admin_keys)
    return report


def register(app: typer.Typer) -> None:
    """Attach the check/reencrypt commands to the main app."""

    from .cli import PANEL_DAILY

    @app.command("check", rich_help_panel=PANEL_DAILY)
    def check(
        secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Only report problems"),
    ):
        """Report drift between src/ and the deploy output.

        Changes nothing.  Exits non-zero if any error-level finding is present,
        so it can gate a build in CI.
        \b
        Examples:
            aegis check
            aegis check --quiet    errors and warnings only
        """
        from .cli import get_secrets_repo

        repo = get_secrets_repo(secrets_path)
        report = run_check(repo)

        if not report.findings:
            typer.secho("No problems found.", fg=typer.colors.GREEN)
            return

        marks = {
            SEVERITY_ERROR: ("✗", typer.colors.RED),
            SEVERITY_WARN: ("!", typer.colors.YELLOW),
            SEVERITY_INFO: ("·", typer.colors.BLUE),
        }
        for finding in report.findings:
            if finding.severity == SEVERITY_INFO and quiet:
                continue
            marker, colour = marks[finding.severity]
            typer.secho(f"{marker} {finding.scope}: {finding.message}", fg=colour)
            if finding.hint and not quiet:
                typer.echo(f"    → {finding.hint}")

        typer.echo("")
        summary = f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)"
        if report.notes:
            summary += f", {len(report.notes)} host(s) not managed"
        typer.secho(
            summary,
            fg=typer.colors.RED if report.errors
            else typer.colors.YELLOW if report.warnings
            else typer.colors.GREEN,
        )

        if report.errors:
            raise typer.Exit(1)

    @app.command("reencrypt", rich_help_panel=PANEL_DAILY)
    def reencrypt(
        secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
        host: Optional[str] = typer.Option(None, "--host", "-H", help="Only this host's files"),
        category: Optional[str] = typer.Option(None, "--category", "-c", help="Only this category (admin-only, host, role, user, kdc, dnssec)"),
        dry_run: bool = typer.Option(False, "--dry-run", "-n"),
        yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
    ):
        """Re-encrypt every secret for the current recipient set.

        Key material is never regenerated: each file is decrypted with the
        admin key and re-encrypted for the audience it is supposed to have.
        Run this after registering a new admin key, or after a host's master
        key changes -- NOT --rotate, which mints new secrets.

        This covers the whole repository, including the admin-only material
        (role private keys, user private keys, realm master keys, every
        Kerberos principal). That material is precisely what a lost admin key
        makes unrecoverable, so a new admin key is not really redundant until
        this has run.

        Per-host manifests are regenerated from src/ placement at the same
        time, so a target path changed in src/hosts/<host>.toml takes effect.
        \b
        Examples:
            aegis reencrypt --dry-run           what would change
            aegis reencrypt --host rama         one host's files
            aegis reencrypt --category admin-only
        """
        from .cli import get_secrets_repo, admin_recipients

        repo = get_secrets_repo(secrets_path)
        admin_keys = admin_recipients(repo)

        policies = recipients.plan(repo, admin_keys)

        if host:
            prefix = repo.host_deploy_path(host)
            policies = [p for p in policies if _is_within(p.path, prefix)]
        if category:
            policies = [p for p in policies if p.category == category]

        unresolvable = [p for p in policies if p.problem]
        actionable = [p for p in policies if p.resolvable]

        # Only touch files whose recipient set actually differs, so a re-run is
        # a no-op and the git diff stays legible.
        stale = [
            p for p in actionable
            if crypto.recipients_of(p.path) != p.expected_count
        ]

        if unresolvable:
            # Group by reason rather than listing every path: 245 identical
            # lines bury the one thing the operator has to decide about.
            reasons: dict[str, list[str]] = {}
            for policy in unresolvable:
                reasons.setdefault(policy.problem or "", []).append(
                    _relative(repo, policy.path))

            typer.secho(
                f"\n{len(unresolvable)} file(s) cannot be re-encrypted "
                f"and keep their current recipients:",
                fg=typer.colors.YELLOW,
            )
            for reason, paths in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
                typer.echo(f"  {len(paths)}x {reason}")
                for path in sorted(paths)[:3]:
                    typer.echo(f"       {path}")
                if len(paths) > 3:
                    typer.echo(f"       ... and {len(paths) - 3} more")

        # Manifest refresh is independent of recipients: a target path changed
        # in src/hosts/<host>.toml has to reach the manifest even when every
        # file already carries the right audience.
        refreshed = 0
        if not dry_run and category in (None, recipients.CAT_HOST):
            for hostname in ([host] if host else repo.list_hosts()):
                if repo.host_deploy_path(hostname).is_dir():
                    _refresh_manifest(repo, hostname)
                    refreshed += 1

        if not stale:
            typer.secho(
                "\nEvery file already carries the expected recipients.",
                fg=typer.colors.GREEN,
            )
            if refreshed:
                typer.echo(f"Refreshed {refreshed} host manifest(s) from src/.")
            return

        grouped = recipients.by_category(stale)
        typer.echo(f"\n{len(stale)} file(s) to re-encrypt:")
        for cat in sorted(grouped):
            typer.echo(f"  {cat}: {len(grouped[cat])}")

        if dry_run:
            for policy in stale:
                typer.echo(
                    f"  [dry-run] {_relative(repo, policy.path)} "
                    f"-> {policy.expected_count} recipients ({policy.label})")
            return

        if not yes:
            typer.echo("")
            typer.echo(
                "Each file is decrypted with your admin key and written back. "
                "Key material is unchanged.")
            if not typer.confirm(f"Re-encrypt {len(stale)} file(s)?"):
                raise typer.Abort()

        rewritten = 0
        failed: list[tuple[str, str]] = []

        for policy in stale:
            rel = _relative(repo, policy.path)
            try:
                plaintext = crypto.decrypt_age_bytes(policy.path)
            except Exception as e:
                # Almost always means the file predates the admin key being a
                # recipient, so this machine cannot recover it.
                failed.append((rel, f"cannot decrypt: {e}"))
                continue

            try:
                _atomic_encrypt(plaintext, policy.recipients, policy.path)
            except Exception as e:
                failed.append((rel, f"cannot write: {e}"))
                continue

            rewritten += 1
            typer.echo(f"  {rel}: {policy.expected_count} recipients")

        typer.secho(f"\nRe-encrypted {rewritten} file(s)", fg=typer.colors.GREEN)
        if refreshed:
            typer.echo(f"Refreshed {refreshed} host manifest(s) from src/.")

        if failed:
            typer.secho(f"{len(failed)} file(s) failed:", fg=typer.colors.RED, err=True)
            for rel, reason in failed:
                typer.echo(f"  {rel}: {reason}", err=True)
            raise typer.Exit(1)


def _is_within(path: Path, prefix: Path) -> bool:
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


def _atomic_encrypt(content: bytes, recipient_keys: list[str], path: Path) -> None:
    """Encrypt to a sibling temp file, then replace.

    Writing in place would leave a truncated file if age failed part way, and
    for admin-only material there is no second copy to fall back on.
    """
    import os
    import tempfile

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name, suffix=".tmp")
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        crypto.encrypt_age(content, recipient_keys, tmp)
        tmp.replace(path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise



def _refresh_manifest(repo: config.SecretsRepo, hostname: str) -> None:
    """Regenerate a host's manifest from src/ placement and what exists on disk."""
    from .cli import host_placement

    deploy = repo.host_deploy_path(hostname)
    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)

    ssh_dir = deploy / "ssh"
    if ssh_dir.is_dir():
        stems = sorted(f.stem for f in ssh_dir.glob("*.age"))
        if stems:
            key_types = [
                s.removeprefix("ssh_host_").removesuffix("_key") for s in stems
            ]
            manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entries(
                stems=stems,
                placement=host_placement(repo, hostname, "ssh-host-keys"),
                key_types=key_types,
            )

    if (deploy / "keytab.age").exists():
        manifest.keytab = host_secrets.make_keytab_entry(
            host_placement(repo, hostname, "keytab"))

    if (deploy / "nexus-key.age").exists():
        manifest.nexus_key = host_secrets.make_nexus_key_entry(
            host_placement(repo, hostname, "nexus-key"))

    secrets_dir = deploy / "secrets"
    if secrets_dir.is_dir():
        for path in sorted(secrets_dir.glob("*.age")):
            name = path.stem
            manifest.secrets[name] = host_secrets.make_secret_entry(
                name=name,
                placement=host_placement(repo, hostname, f"secret:{name}"),
            )

    # Role membership drives both the roles list and an entry per role secret,
    # so a target changed in src/roles/<role>.toml reaches every member here.
    for conflict in host_secrets.reconcile_roles(repo, hostname, manifest):
        typer.secho(f"  Warning: {hostname}: {conflict}",
                    fg=typer.colors.YELLOW, err=True)

    host_secrets.save_host_manifest(repo.deploy_path, manifest)
