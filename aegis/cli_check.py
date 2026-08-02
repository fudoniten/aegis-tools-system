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

from . import admin, config, crypto, host_secrets, realm as realm_mod
from .errors import AegisError

SEVERITY_ERROR = "error"
SEVERITY_WARN = "warn"


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

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == SEVERITY_WARN]


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

        if not (host_config and host_config.age_pubkey):
            report.error(
                scope,
                "no master key set",
                f"aegis set-master-key {hostname} --public-key 'age1...'",
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
                "aegis build-role-keys",
            )

    for hostname in repo.list_deployed_hosts():
        if hostname not in configured:
            deploy = repo.host_deploy_path(hostname)
            count = sum(1 for _ in deploy.rglob("*") if _.is_file())
            report.error(
                f"host/{hostname}",
                f"has output in {repo.deploy_path.name}/ but no config in src/hosts/ "
                f"({count} files)",
                f"remove it, or re-add with: aegis init-host {hostname}",
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
                f"aegis init-role {role_name}",
            )
        if not repo.role_pubkey_path(role_name).exists():
            report.error(
                scope,
                "no public key, so nothing can be encrypted to this role",
                f"aegis init-role {role_name}",
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
                "aegis build-role-keys",
            )

        unknown = [h for h in role_config.hosts if h not in configured_hosts]
        if unknown:
            report.warn(
                scope,
                f"members not configured in src/hosts/: {', '.join(sorted(unknown))}")

    # Files in the roles output directory that no role in src/ accounts for.
    # These accumulate when a role is renamed: the new name gets a config, the
    # old one's key material is left behind and still decrypts whatever it was
    # encrypted for.
    roles_dir = repo.roles_deploy_path()
    if roles_dir.is_dir():
        configured_roles = set(repo.list_roles())
        for path in sorted(roles_dir.iterdir()):
            if path.suffix not in (".age", ".pub"):
                continue
            if path.stem not in configured_roles:
                report.warn(
                    "roles",
                    f"{path.name} has no matching config in src/roles/ "
                    f"(orphaned by a rename?)",
                    f"remove it, or recreate the role: aegis init-role {path.stem}",
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
                    f"aegis remove-host-from-role {key_file.stem} {hostname}",
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
                f"aegis init-role {realm_config.kdc_role}",
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
                "aegis build-keytabs",
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
        allowed = set(user_config.hosts)

        if not repo.user_key_path(username).exists():
            report.error(
                scope,
                "no private key in keys/users/, so their repo cannot be decrypted",
                f"aegis add-user {username} --hosts=...",
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
    """
    if not admin_keys:
        return

    n_admin = len(admin_keys)

    for hostname in repo.list_hosts():
        deploy = repo.host_deploy_path(hostname)
        if not deploy.is_dir():
            continue

        scope = f"host/{hostname}"
        expected = 1 + n_admin  # host + admin set

        for path in sorted(deploy.glob("ssh/*.age")) + sorted(deploy.glob("*.age")):
            if path.name == "keytab.age":
                continue
            found = crypto.recipients_of(path)
            if found and found < expected:
                report.error(
                    scope,
                    f"{path.relative_to(repo.deploy_path)} has {found} recipients, "
                    f"expected at least {expected} (host + {n_admin} admin)",
                    f"aegis reencrypt --host {hostname}",
                )

        keytab = deploy / "keytab.age"
        if keytab.exists():
            found = crypto.recipients_of(keytab)
            # host + admin set + kdc role
            if found and found < expected + 1:
                report.error(
                    scope,
                    f"keytab.age has {found} recipients, expected at least "
                    f"{expected + 1} (host + {n_admin} admin + KDC role); the KDC "
                    f"cannot read this keytab",
                    "aegis build-keytabs --force",
                )


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

    @app.command("check")
    def check(
        secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
        quiet: bool = typer.Option(False, "--quiet", "-q", help="Only report problems"),
    ):
        """Report drift between src/ and the deploy output.

        Changes nothing.  Exits non-zero if any error-level finding is present,
        so it can gate a build in CI.
        """
        from .cli import get_secrets_repo

        repo = get_secrets_repo(secrets_path)
        report = run_check(repo)

        if not report.findings:
            typer.secho("No problems found.", fg=typer.colors.GREEN)
            return

        for finding in report.findings:
            colour = (
                typer.colors.RED if finding.severity == SEVERITY_ERROR
                else typer.colors.YELLOW
            )
            marker = "✗" if finding.severity == SEVERITY_ERROR else "!"
            typer.secho(f"{marker} {finding.scope}: {finding.message}", fg=colour)
            if finding.hint and not quiet:
                typer.echo(f"    → {finding.hint}")

        typer.echo("")
        typer.secho(
            f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)",
            fg=typer.colors.RED if report.errors else typer.colors.YELLOW,
        )

        if report.errors:
            raise typer.Exit(1)

    @app.command("reencrypt")
    def reencrypt(
        secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
        host: Optional[str] = typer.Option(None, "--host", "-H", help="Only this host"),
        dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    ):
        """Re-encrypt existing secrets for the current recipient set.

        Key material is never regenerated: each file is decrypted with the
        admin key and re-encrypted for the host plus every registered admin
        key.  Use this after adding an admin key, or after a host's master key
        changes -- NOT --rotate, which mints new secrets.

        The per-host manifest is regenerated from src/ placement at the same
        time, so a target path changed in src/hosts/<host>.toml takes effect.
        """
        from .cli import get_secrets_repo, admin_recipients, get_host_age_pubkey

        repo = get_secrets_repo(secrets_path)
        admin_keys = admin_recipients(repo)

        hosts = [host] if host else repo.list_hosts()
        total = 0

        for hostname in hosts:
            deploy = repo.host_deploy_path(hostname)
            if not deploy.is_dir():
                continue

            try:
                host_key = get_host_age_pubkey(hostname, repo)
            except AegisError as e:
                typer.echo(f"  Skipping {hostname}: {e}", err=True)
                continue

            host_config = repo.get_host_config(hostname)
            assert host_config is not None

            kdc_pubkey = _kdc_pubkey_for(repo, hostname)

            changed = 0
            for path in sorted(deploy.rglob("*.age")):
                relative = path.relative_to(deploy)

                # Role keys and user manifests have their own recipient rules;
                # rebuild them with their own commands rather than guessing.
                if relative.parts[0] in ("roles", "users"):
                    continue

                recipients = [host_key, *admin_keys]
                if path.name == "keytab.age" and kdc_pubkey:
                    recipients.append(kdc_pubkey)

                if crypto.recipients_of(path) == len(set(recipients)):
                    continue

                if dry_run:
                    typer.echo(f"  [dry-run] would re-encrypt {hostname}/{relative}")
                    changed += 1
                    continue

                try:
                    plaintext = crypto.decrypt_age_bytes(path)
                except Exception as e:
                    typer.echo(f"  {hostname}/{relative}: cannot decrypt: {e}", err=True)
                    continue

                crypto.encrypt_age(plaintext, recipients, path)
                typer.echo(f"  {hostname}/{relative}: {len(set(recipients))} recipients")
                changed += 1

            if not dry_run:
                _refresh_manifest(repo, hostname)

            if changed:
                total += changed
                typer.echo(f"  {hostname}: {changed} file(s)")

        verb = "would re-encrypt" if dry_run else "re-encrypted"
        typer.secho(f"\n{verb} {total} file(s)", fg=typer.colors.GREEN)


def _kdc_pubkey_for(repo: config.SecretsRepo, hostname: str) -> str | None:
    """The KDC role public key for whichever realm this host belongs to."""
    for membership in realm_mod.memberships(repo):
        if membership.hostname != hostname:
            continue
        realm_config = realm_mod.load(repo, membership.realm)
        pub_path = repo.role_pubkey_path(realm_config.kdc_role)
        if pub_path.exists():
            return pub_path.read_text().strip()
    return None


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

    roles_dir = deploy / "roles"
    manifest.roles = (
        sorted(f.stem for f in roles_dir.glob("*.age")) if roles_dir.is_dir() else []
    )

    host_secrets.save_host_manifest(repo.deploy_path, manifest)
