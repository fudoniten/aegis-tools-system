"""Aegis CLI - System administration tools for secrets management."""

import os
import sys
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from typer.core import TyperGroup

from . import admin, crypto, removal, ssh, config
from .cli_removal import run_removal
from .errors import AegisError, MissingHostKeyError

# Top-level help is a menu, not a manual: every entry is either a verb you run
# daily or a noun you manage, and the panels say which.  Detail belongs in
# 'aegis <group> --help', where it is asked for.
PANEL_DAILY = "Daily use"
PANEL_INVENTORY = "Inventory"
PANEL_MATERIAL = "Key material"

# Where each pre-grouping command name moved to.  The old spelling still
# works -- with a note on stderr -- so scripts and muscle memory survive the
# reshuffle.  Drop this table (and AegisGroup) once beta is over.
LEGACY_COMMANDS: dict[str, list[str]] = {
    "build-role-keys": ["build", "role-keys"],
    "build-ssh-host-keys": ["build", "ssh-keys"],
    "build-nexus-keys": ["build", "nexus-keys"],
    "build-keytabs": ["build", "keytabs"],
    "build-user-secrets": ["build", "user-secrets"],
    "build-bundles": ["build", "bundles"],
    "init-host": ["host", "add"],
    "set-master-key": ["host", "set-key"],
    "set-host-status": ["host", "set-status"],
    "set-placement": ["host", "set-placement"],
    "add-user": ["user", "add"],
    "init-role": ["role", "init"],
    "add-host-to-role": ["role", "add-host"],
    "remove-host-from-role": ["role", "remove-host"],
    "new-secret": ["secret", "new"],
    "import-secret": ["secret", "import"],
    "add-secret": ["secret", "add"],
    "list": ["secret", "list"],
    "import-ssh-host-keys": ["ssh", "import"],
    "import-nexus-key": ["nexus", "import"],
    "nexus-keygen": ["nexus", "keygen"],
    "generate-dnssec-keys": ["dnssec", "generate"],
    "import-dnssec-keys": ["dnssec", "import"],
    "init-realm": ["realm", "init"],
    "import-kerberos-realm": ["realm", "import"],
}


class OrderedGroup(TyperGroup):
    """Group whose help follows a curated order.

    Otherwise commands are listed in registration order, which is an artifact
    of which module imported what.  Anything not named sorts last.
    """

    command_order: tuple[str, ...] = ()

    def list_commands(self, ctx):
        order = self.command_order
        return sorted(
            super().list_commands(ctx),
            key=lambda name: (
                order.index(name) if name in order else len(order), name),
        )


class AegisGroup(OrderedGroup):
    """Top-level group that still answers to the pre-grouping command names."""

    command_order = (
        "build", "status", "check", "verify", "reencrypt",
        "host", "user", "role", "secret",
        "ssh", "nexus", "dnssec", "realm", "admin",
    )

    def resolve_command(self, ctx, args):
        if args and args[0] in LEGACY_COMMANDS and args[0] not in self.commands:
            old = args[0]
            replacement = LEGACY_COMMANDS[old]
            typer.secho(
                f"note: 'aegis {old}' is now 'aegis {' '.join(replacement)}'",
                fg=typer.colors.YELLOW,
                err=True,
            )
            args = replacement + list(args[1:])
        return super().resolve_command(ctx, args)


class SecretGroup(OrderedGroup):
    """'secret' reads best as create, then bring in, then look at."""

    command_order = ("new", "import", "add", "list")


app = typer.Typer(
    name="aegis",
    cls=AegisGroup,
    help="Aegis System Administration Tools for secrets management.",
    # One line per paragraph, and no \b markers: typer renders the epilog
    # through Rich, and versions before 0.27 flatten every single newline in it
    # into a space -- turning a column of commands into a wall of prose -- while
    # honouring \b only in the *help* text, never here.  Blank-line-separated
    # paragraphs are the one structure both versions keep, so each line that has
    # to stand on its own is one.  Keep them short: a paragraph that outgrows a
    # line is reflowed, and the alignment goes with it.
    epilog="""A new host, end to end:

  aegis host add rama --domain sea.fudo.org      declare it

  aegis host set-key rama --public-key age1...   so it can decrypt

  aegis build                                    generate what it is missing

  aegis check                                    confirm nothing is adrift

Environment. Each names a path; the command-line option wins where there is one:

  AEGIS_SYSTEM             the aegis-secrets repo, as --secrets-path/-s does

  AEGIS_ADMIN_KEY          this machine's admin key (~/.config/aegis/key.txt)

  AEGIS_SCRIPTS            the bundled Kerberos scripts; set by the Nix wrapper

  AEGIS_USER_REPO_<USER>   one user's secrets repo, for build user-secrets

Run 'aegis COMMAND --help' to see what a group can do, e.g. 'aegis host --help'.""",
    no_args_is_help=True,
    # Typer's rich traceback handler runs inside click's invocation, so an
    # AegisError reaching the top would be rendered as a full traceback before
    # main() ever saw it. Operator-facing failures deserve one line.
    pretty_exceptions_enable=False,
)

# The build group's own help comes from its callback's docstring, below.
# A bare 'aegis build' runs that callback (the full build), so it must not be
# turned into a help screen.
build_app = typer.Typer(no_args_is_help=False)
host_app = typer.Typer(
    help="Declare hosts, their master keys, status and secret placement.",
    no_args_is_help=True,
)
user_app = typer.Typer(
    help="Declare users and the hosts they can reach.",
    no_args_is_help=True,
)
role_app = typer.Typer(
    help="Roles: shared keys held by a set of hosts.",
    no_args_is_help=True,
)
secret_app = typer.Typer(
    cls=SecretGroup,
    help="Individual secrets: create, import, inspect.",
    no_args_is_help=True,
)
ssh_app = typer.Typer(
    help="SSH host keys (the identity sshd presents).",
    no_args_is_help=True,
)
nexus_app = typer.Typer(
    help="Nexus DDNS authentication keys.",
    no_args_is_help=True,
)
dnssec_app = typer.Typer(
    help="DNSSEC key signing keys.",
    no_args_is_help=True,
)


def _register_subcommands() -> None:
    """Attach subcommand groups.

    Imported lazily inside the function because cli_realm/cli_check import
    helpers from this module.
    """
    from .cli_admin import admin_app
    from .cli_realm import realm_app
    from .cli_nebula import nebula_app
    from . import cli_check

    app.add_typer(build_app, name="build", rich_help_panel=PANEL_DAILY)
    app.add_typer(host_app, name="host", rich_help_panel=PANEL_INVENTORY)
    app.add_typer(user_app, name="user", rich_help_panel=PANEL_INVENTORY)
    app.add_typer(role_app, name="role", rich_help_panel=PANEL_INVENTORY)
    app.add_typer(secret_app, name="secret", rich_help_panel=PANEL_INVENTORY)
    app.add_typer(ssh_app, name="ssh", rich_help_panel=PANEL_MATERIAL)
    app.add_typer(nexus_app, name="nexus", rich_help_panel=PANEL_MATERIAL)
    app.add_typer(dnssec_app, name="dnssec", rich_help_panel=PANEL_MATERIAL)
    app.add_typer(admin_app, name="admin", rich_help_panel=PANEL_MATERIAL)
    app.add_typer(realm_app, name="realm", rich_help_panel=PANEL_MATERIAL)
    app.add_typer(nebula_app, name="nebula", rich_help_panel=PANEL_MATERIAL)
    cli_check.register(app)


def _is_aegis_repo(path: Path) -> bool:
    """Check if a path looks like an aegis secrets repo.

    Requires *both* a src/ directory and one of keys/ or the output directory.
    A bare src/ is not enough: plenty of unrelated projects have one, and
    misidentifying them means ensure_structure() scaffolds an aegis tree into
    somebody else's repo.
    """
    has_src = (path / "src").is_dir()
    has_support = (
        (path / "keys").is_dir()
        or (path / config.SecretsRepo.DEPLOY_DIRNAME).is_dir()
        or (path / config.SecretsRepo.LEGACY_DEPLOY_DIRNAME).is_dir()
    )
    return has_src and has_support


def get_secrets_repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    """Get the secrets repo, with default path handling.
    
    Resolution order:
    1. Explicit --secrets-path argument
    2. AEGIS_SYSTEM environment variable
    3. Current directory (if it looks like a secrets repo)
    4. Common relative paths (./aegis-secrets, ../aegis-secrets)
    """
    if secrets_path is not None:
        if not secrets_path.exists():
            typer.echo(f"Error: Specified path does not exist: {secrets_path}", err=True)
            raise typer.Exit(1)
        return config.SecretsRepo(secrets_path)
    
    # Check AEGIS_SYSTEM environment variable
    env_path = os.environ.get("AEGIS_SYSTEM")
    if env_path:
        path = Path(env_path)
        if path.exists() and _is_aegis_repo(path):
            return config.SecretsRepo(path)
        typer.echo(f"Error: AEGIS_SYSTEM points to invalid repo: {env_path}", err=True)
        raise typer.Exit(1)
    
    # Try to find it relative to current directory
    candidates = [
        Path.cwd(),  # Maybe we're in the secrets repo
        Path.cwd() / "aegis-secrets",
        Path.cwd().parent / "aegis-secrets",
    ]
    for candidate in candidates:
        if candidate.exists() and _is_aegis_repo(candidate):
            return config.SecretsRepo(candidate)
    
    typer.echo("Error: Could not find aegis-secrets repo", err=True)
    typer.echo("", err=True)
    typer.echo("Options:", err=True)
    typer.echo("  1. Run from within an aegis-secrets repo", err=True)
    typer.echo("  2. Set AEGIS_SYSTEM environment variable", err=True)
    typer.echo("  3. Use --secrets-path to specify location", err=True)
    raise typer.Exit(1)



def get_host_age_pubkey(
    hostname: str,
    repo: config.SecretsRepo,
) -> str:
    """Get the age public key for a host from its config in aegis-secrets.

    Returns:
        age public key string (e.g., "age1...")

    Raises:
        MissingHostKeyError: if the host has no age public key configured.
        Callers looping over hosts should catch it and skip; top-level
        commands let it propagate to :func:`main`, which reports and exits.
    """
    host_config = repo.get_host_config(hostname)
    if host_config and host_config.age_pubkey:
        return host_config.age_pubkey

    raise MissingHostKeyError(hostname)


def admin_recipients(repo: config.SecretsRepo, *, validate: bool = True) -> list[str]:
    """The admin public keys to encrypt for, validated against the local key.

    Every secret is encrypted for the admin set as well as its real audience,
    so this is the system's recovery path.  Validation catches the case where
    the operator holds a key that the repo does not know about — otherwise
    they would produce files no other admin can read, and only find out much
    later.
    """
    keys = admin.recipients(repo)
    if validate:
        admin.validate_local_key(repo)
    return keys


def host_placement(
    repo: config.SecretsRepo,
    hostname: str,
    kind: str,
) -> config.Placement:
    """Deployment metadata for a host's secret, from src/hosts/<host>.toml."""
    host_config = repo.get_host_config(hostname)
    if host_config is None:
        return config.Placement()
    return host_config.placement_for(kind)


def record_placement(
    repo: config.SecretsRepo,
    hostname: str,
    kind: str,
    placement: config.Placement,
) -> None:
    """Persist placement overrides into src/ so the manifest stays derived."""
    if placement.is_empty():
        return
    host_config = repo.get_host_config(hostname) or config.HostConfig(hostname=hostname)
    existing = host_config.placement_for(kind)
    merged = config.Placement(
        target=placement.target or existing.target,
        target_dir=placement.target_dir or existing.target_dir,
        user=placement.user or existing.user,
        group=placement.group or existing.group,
        mode=placement.mode or existing.mode,
    )
    host_config.set_placement(kind, merged)
    repo.set_host_config(host_config)


def role_placement(
    repo: config.SecretsRepo,
    role_name: str,
    kind: str,
) -> config.Placement:
    """Deployment metadata for a role's secret, from src/roles/<role>.toml."""
    role_config = repo.get_role_config(role_name)
    if role_config is None:
        return config.Placement()
    return role_config.placement_for(kind)


def record_role_placement(
    repo: config.SecretsRepo,
    role_name: str,
    kind: str,
    placement: config.Placement,
) -> None:
    """Persist a role secret's placement into src/roles/<role>.toml.

    Kept alongside the role rather than copied into each member's host config:
    a role secret has one destination, and a host joining the role later must
    inherit it without anybody re-stating it.
    """
    if placement.is_empty():
        return
    role_config = repo.get_role_config(role_name) or config.RoleConfig(name=role_name)
    existing = role_config.placement_for(kind)
    merged = config.Placement(
        target=placement.target or existing.target,
        target_dir=placement.target_dir or existing.target_dir,
        user=placement.user or existing.user,
        group=placement.group or existing.group,
        mode=placement.mode or existing.mode,
    )
    role_config.set_placement(kind, merged)
    repo.set_role_config(role_config)


def reconcile_host_roles(repo: config.SecretsRepo, hostname: str) -> list[str]:
    """Point a host's manifest at the secrets of every role it belongs to.

    Returns any name collisions, which are reported rather than resolved --
    see :func:`aegis.host_secrets.reconcile_roles`.
    """
    from . import host_secrets

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    before = manifest.to_dict()
    conflicts = host_secrets.reconcile_roles(repo, hostname, manifest)

    # Only write when something changed, so a re-run is a no-op and the git
    # diff in aegis-secrets stays legible.
    if manifest.to_dict() != before:
        host_secrets.save_host_manifest(repo.deploy_path, manifest)

    return conflicts


def reconcile_role_members(repo: config.SecretsRepo, role_name: str) -> list[str]:
    """Refresh every member host's manifest after a role's secrets changed.

    Returns the hosts whose manifests were considered.  Hosts Aegis does not
    deploy to are skipped: writing a manifest for a retired machine would
    describe a deployment that must not happen.
    """
    role_config = repo.get_role_config(role_name)
    if role_config is None:
        return []

    deploying = set(repo.list_deploying_hosts())
    touched: list[str] = []
    for hostname in role_config.hosts:
        if hostname not in deploying:
            continue
        for conflict in reconcile_host_roles(repo, hostname):
            typer.secho(f"  Warning: {hostname}: {conflict}",
                        fg=typer.colors.YELLOW, err=True)
        touched.append(hostname)
    return touched


def ensure_host_config(repo: config.SecretsRepo, hostname: str) -> config.HostConfig:
    """Fetch a host config, creating an empty one if it does not exist."""
    host_config = repo.get_host_config(hostname)
    if host_config is None:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
        repo.set_host_config(host_config)
        typer.echo(f"  Created {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    return host_config


# =============================================================================
# aegis build ...
# =============================================================================

@build_app.callback(invoke_without_command=True)
def build(
    ctx: typer.Context,
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
):
    """Generate missing secrets for all configured hosts.

    With no subcommand this runs every step, in order:
    role keys, role secrets, SSH host keys, Nexus keys, keytabs, user secrets.
    Name a subcommand to run one of them on its own.

    Nothing here replaces key material that already exists; see
    'aegis build ssh-keys --rotate' for that, and 'aegis reencrypt'
    to change who a secret is encrypted for.
    \b
    Examples:
        aegis build                       everything that is missing
        aegis build --dry-run             say what that would be
        aegis build keytabs --realm SEA.FUDO.ORG
    """
    if ctx.invoked_subcommand is not None:
        return
    _build_everything(secrets_path, dry_run)


def _build_everything(secrets_path: Optional[Path], dry_run: bool) -> None:
    """Run every build step in dependency order."""
    get_secrets_repo(secrets_path)  # fail early if the repo cannot be found

    typer.echo("Running full build...")

    if dry_run:
        typer.echo("  [dry-run] Would run: build role-keys")
        typer.echo("  [dry-run] Would run: build role-secrets")
        typer.echo("  [dry-run] Would run: build ssh-keys")
        typer.echo("  [dry-run] Would run: build nexus-keys")
        typer.echo("  [dry-run] Would run: build keytabs")
        typer.echo("  [dry-run] Would run: build nebula")
        typer.echo("  [dry-run] Would run: build user-secrets")
        return

    # Run each build step
    typer.echo("\n--- Building Role Keys ---")
    build_role_keys(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building Role Secrets ---")
    build_role_secrets(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building SSH Host Keys ---")
    build_ssh_host_keys(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building Nexus Keys ---")
    build_nexus_keys(secrets_path=secrets_path, dry_run=False, algorithm="HmacSHA512")

    typer.echo("\n--- Building Keytabs ---")
    build_keytabs(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building Nebula Certificates ---")
    build_nebula_certs(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building User Secrets ---")
    build_user_secrets(secrets_path=secrets_path, dry_run=False, user=None)

    typer.secho("\nBuild complete!", fg=typer.colors.GREEN)


@build_app.command("nebula")
def build_nebula_certs(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    network: Annotated[Optional[str], typer.Option("--network", "-N", help="Only this network")] = None,
    renew_within: Annotated[int, typer.Option("--renew-within", help="Re-sign certificates with fewer days left than this")] = 30,
    rotate: Annotated[bool, typer.Option("--rotate", "--force", "-f", help="DESTRUCTIVE: generate NEW key material, dropping hosts off the mesh until redeployed")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt for --rotate")] = False,
):
    """Sign Nebula certificates and generate the keys behind them.

    Unlike the other generators, this is not purely "create if missing":
    Nebula certificates expire. One with fewer than --renew-within days left is
    re-signed against the host's existing key, which the mesh does not notice.
    Only --rotate mints new key material, which drops a host until it is
    deployed again.

    Hosts marked --local-key keep their own private key; they are signed from
    the public key imported with 'aegis nebula import-pubkey', and no key is
    deployed to them.
    \b
    Examples:
        aegis build nebula                     sign what is missing or expiring
        aegis build nebula --renew-within 60
        aegis build nebula --rotate --yes      NEW keys; drops hosts until deploy
    """
    from .cli_nebula import build_nebula

    if rotate and not dry_run and not yes:
        typer.secho(
            "--rotate replaces Nebula key material: every affected host drops "
            "off the mesh until it is deployed again. To re-encrypt without "
            "changing keys, use 'aegis reencrypt'; to extend expiry, plain "
            "'aegis build nebula' renews against the existing key.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("Generate new Nebula keys?"):
            raise typer.Abort()

    build_nebula(
        secrets_path=secrets_path,
        dry_run=dry_run,
        network=network,
        renew_within=renew_within,
        rotate=rotate,
    )


@build_app.command("all")
def build_all(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
):
    """Run every build step (the same as bare 'aegis build')."""
    # Spelled out so the full build is listed in 'aegis build --help' rather
    # than only mentioned in the group's description.
    _build_everything(secrets_path, dry_run)


@build_app.command("role-keys")
def build_role_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
):
    """Ensure every role member host has its per-host role key file.

    For each role, decrypts the admin-held role private key and re-encrypts
    it for every host listed in the role config, writing the result to
    build/hosts/<hostname>/roles/<role>.age.

    Also updates each host's secrets.toml manifest with the list of roles it
    belongs to, so the NixOS module can discover them automatically.
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    admin_keys = admin_recipients(repo)
    deploying = set(repo.list_deploying_hosts())

    for role_name in repo.list_roles():
        role_config = repo.get_role_config(role_name)
        if not role_config:
            continue

        role_key_path = repo.role_key_path(role_name)
        if not role_key_path.exists():
            typer.echo(f"  Warning: No master key for role {role_name}, skipping")
            continue

        role_privkey: str | None = None  # decrypt lazily

        for hostname in role_config.hosts:
            if hostname not in deploying:
                typer.echo(
                    f"  Skipping {hostname}: status is "
                    f"{repo.host_status(hostname)}")
                continue
            out_path = repo.host_role_key_path(hostname, role_name)
            if out_path.exists():
                continue

            if dry_run:
                typer.echo(f"  [dry-run] Would create role key: {hostname}/{role_name}")
                continue

            typer.echo(f"  Creating role key: {hostname} → {role_name}...")

            if role_privkey is None:
                try:
                    role_privkey = crypto.decrypt_age(role_key_path)
                except Exception as e:
                    typer.echo(f"    Error decrypting role key {role_name}: {e}", err=True)
                    break

            try:
                host_age_key = get_host_age_pubkey(hostname, repo)
            except AegisError as e:
                typer.echo(f"    Skipping {hostname}: {e}", err=True)
                continue

            out_path.parent.mkdir(parents=True, exist_ok=True)
            crypto.encrypt_age(role_privkey, [host_age_key, *admin_keys], out_path)
            typer.echo(f"    Wrote: {out_path}")

    if dry_run:
        return

    # Update each host's manifest with the roles it belongs to
    for hostname in repo.list_hosts():
        roles_dir = repo.host_deploy_path(hostname) / "roles"
        roles = sorted(f.stem for f in roles_dir.glob("*.age")) if roles_dir.exists() else []
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        if manifest.roles != roles:
            manifest.roles = roles
            host_secrets.save_host_manifest(repo.deploy_path, manifest)
            if roles:
                typer.echo(f"  {hostname}: roles={', '.join(roles)}")


@build_app.command("role-secrets")
def build_role_secrets(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
):
    """Point every role member's manifest at the secrets of its roles.

    Role secrets are stored once, encrypted to the role, at
    deploy/roles/<role>/secrets/<name>.age. Nothing is re-encrypted here: this
    step only reconciles which hosts *declare* those secrets, adding entries
    for hosts that joined a role and dropping them from hosts that left.

    Run it after 'aegis secret import --role', or after any change to role
    membership; 'aegis build' runs it for you.
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)

    total = 0
    for hostname in repo.list_deploying_hosts():
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        before = {name: entry.to_dict() for name, entry in manifest.secrets.items()}
        before_roles = list(manifest.roles)
        conflicts = host_secrets.reconcile_roles(repo, hostname, manifest)
        after = {name: entry.to_dict() for name, entry in manifest.secrets.items()}

        for conflict in conflicts:
            typer.secho(f"  Warning: {hostname}: {conflict}",
                        fg=typer.colors.YELLOW, err=True)

        if before == after and before_roles == manifest.roles:
            continue

        added = sorted(set(after) - set(before))
        removed = sorted(set(before) - set(after))
        changed = sorted(
            name for name in set(after) & set(before) if after[name] != before[name])

        detail = ", ".join(
            [f"+{name}" for name in added]
            + [f"-{name}" for name in removed]
            + [f"~{name}" for name in changed]
        ) or f"roles={', '.join(manifest.roles) or '[]'}"

        if dry_run:
            typer.echo(f"  [dry-run] Would update {hostname}: {detail}")
            continue

        host_secrets.save_host_manifest(repo.deploy_path, manifest)
        typer.echo(f"  {hostname}: {detail}")
        total += 1

    if not dry_run and total == 0:
        typer.echo("  Every manifest already matches role membership.")


@build_app.command("ssh-keys")
def build_ssh_host_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    rotate: Annotated[bool, typer.Option("--rotate", "--force", "-f", help="DESTRUCTIVE: generate NEW key material, replacing the host's SSH identity")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt for --rotate")] = False,
):
    """Generate SSH host keys for OpenSSH servers.

    This generates the keys that OpenSSH will use to identify the server
    (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).

    These are NOT master keys! Master keys are used to encrypt these host keys.

    Each private key is encrypted separately as its own age file under
    deploy/hosts/<hostname>/ssh/.  The corresponding public keys are written
    as plaintext .pub files alongside for use in DNS or known_hosts files.

    Deployment metadata comes from src/hosts/<hostname>.toml (see
    'aegis host set-placement') and is written to deploy/hosts/<hostname>/secrets.toml
    for NixOS to import.

    Also generates SSHFP DNS records for trust establishment.

    To re-encrypt existing keys for a changed recipient set, use
    'aegis reencrypt' -- NOT --rotate, which mints new keys.
    \b
    Examples:
        aegis build ssh-keys                    fill in whatever is missing
        aegis build ssh-keys --rotate --yes     NEW keys; breaks known_hosts
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)

    hosts = repo.list_deploying_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis host add' first.")
        return

    admin_keys = admin_recipients(repo)

    if rotate and not dry_run and not yes:
        typer.secho(
            "--rotate replaces SSH host identities: known_hosts entries and "
            "SSHFP records for every host with existing keys will break.\n"
            "To re-encrypt without changing keys, use 'aegis reencrypt'.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("Generate new SSH host keys?"):
            raise typer.Abort()

    for hostname in hosts:
        ssh_dir = repo.host_deploy_path(hostname) / "ssh"

        if ssh_dir.exists() and any(ssh_dir.glob("*.age")) and not rotate:
            typer.echo(f"  {hostname}: SSH host keys exist (use --rotate to replace them)")
            continue

        if dry_run:
            typer.echo(f"  [dry-run] Would generate SSH host keys for {hostname}")
            continue

        typer.echo(f"  Generating SSH host keys for {hostname}...")

        # Get age public key from host config
        try:
            host_age_key = get_host_age_pubkey(hostname, repo)
        except AegisError as e:
            typer.echo(f"    Skipping {hostname}: {e}", err=True)
            continue

        # Generate keys
        keys = ssh.generate_host_keys(hostname)

        # Encrypt each private key separately; write each public key plaintext
        recipients = [host_age_key, *admin_keys]
        ssh_dir.mkdir(parents=True, exist_ok=True)

        for stem, keypair in keys.items():
            age_path = ssh_dir / f"{stem}.age"
            pub_path = ssh_dir / f"{stem}.pub"
            crypto.encrypt_age(keypair.private_key, recipients, age_path)
            pub_path.write_text(keypair.public_key + "\n")
            typer.echo(f"    Wrote {age_path.name} + {pub_path.name}")

        # Update the manifest, keeping the two categories of key apart.
        #
        # Every key above is encrypted and delivered identically, but only the
        # ssh_host_* pair are identities sshd presents. Declaring the deploy
        # and initrd keys under [[ssh-host-keys]] -- which this did, with all
        # four sharing the `ed25519`/`ecdsa` types their keypairs actually have
        # -- puts them in services.openssh.hostKeys, and collapses the three
        # ed25519 entries into a single aegis-ssh-ed25519 unit so two of the
        # targets are never written at all.
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        placement = host_placement(repo, hostname, "ssh-host-keys")

        manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entries(
            stems=[stem for stem, _ in keys.host_key_items()],
            placement=placement,
            key_types=[kp.key_type for _, kp in keys.host_key_items()],
        )
        manifest.secrets.update(host_secrets.make_ssh_auxiliary_entries(
            stems=[stem for stem, _ in keys.auxiliary_items()],
            placement=placement,
        ))

        manifest_path = host_secrets.save_host_manifest(repo.deploy_path, manifest)
        typer.echo(f"    Updated manifest: {manifest_path}")

        # Generate SSHFP records
        public_keys = [
            keys.host_ed25519.public_key,
            keys.host_ecdsa.public_key,
        ]
        sshfp_records = ssh.generate_sshfp_records(public_keys, hostname)
        typer.echo(f"    SSHFP records:")
        for record in sshfp_records:
            typer.echo(f"      {record}")


@build_app.command("nexus-keys")
def build_nexus_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    rotate: Annotated[bool, typer.Option("--rotate", "--force", "-f", help="DESTRUCTIVE: generate a NEW key, invalidating the host's DDNS registration")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt for --rotate")] = False,
    algorithm: Annotated[str, typer.Option("--algorithm", "-a", help="HMAC algorithm")] = "HmacSHA512",
):
    """Generate Nexus DDNS authentication keys for hosts.

    Creates HMAC keys for each host to authenticate with Nexus DDNS servers.
    Keys are encrypted for the host and the admin recipient set.

    Each host gets a unique key stored in deploy/hosts/<hostname>/nexus-key.age.
    Deployment metadata comes from src/hosts/<hostname>.toml (see
    'aegis host set-placement') and is written to secrets.toml for NixOS to import.

    To re-encrypt an existing key for a changed recipient set, use
    'aegis reencrypt' -- NOT --rotate, which mints a new key.
    \b
    Examples:
        aegis build nexus-keys
        aegis build nexus-keys --rotate --yes   NEW key; breaks DDNS until deploy
    """
    from . import nexus

    repo = get_secrets_repo(secrets_path)

    hosts = repo.list_deploying_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis host add' first.")
        return

    admin_keys = admin_recipients(repo)

    if rotate and not dry_run and not yes:
        typer.secho(
            "--rotate replaces Nexus DDNS keys: every host with an existing key "
            "will fail to authenticate until it is redeployed.\n"
            "To re-encrypt without changing keys, use 'aegis reencrypt'.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm("Generate new Nexus keys?"):
            raise typer.Abort()

    for hostname in hosts:
        output_path = repo.host_deploy_path(hostname) / "nexus-key.age"

        if output_path.exists() and not rotate:
            typer.echo(f"  {hostname}: Nexus key exists (use --rotate to replace it)")
            continue

        if dry_run:
            typer.echo(f"  [dry-run] Would generate Nexus key for {hostname}")
            continue

        typer.echo(f"  Generating Nexus key for {hostname}...")

        # Get age public key from host config
        try:
            host_age_key = get_host_age_pubkey(hostname, repo)
        except AegisError as e:
            typer.echo(f"    Skipping {hostname}: {e}", err=True)
            continue

        # Generate key in a temp file
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_key_path = Path(tmpdir) / "nexus.key"
            nexus.generate_key(
                output_path=tmp_key_path,
                algorithm=algorithm,
                verbose=False,
            )

            # Read the generated key
            key_content = tmp_key_path.read_text()

        # Get recipients
        recipients = [host_age_key, *admin_keys]
        
        # Encrypt and write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(key_content, recipients, output_path)
        
        typer.echo(f"    Wrote {output_path}")
        
        # Update manifest with deployment metadata
        from . import host_secrets
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        manifest.nexus_key = host_secrets.make_nexus_key_entry(
            host_placement(repo, hostname, "nexus-key")
        )
        host_secrets.save_host_manifest(repo.deploy_path, manifest)
        typer.echo(f"    Updated manifest")
        
        # Show the algorithm
        algo, _ = key_content.strip().split(":", 1)
        typer.echo(f"    Algorithm: {algo}")


@build_app.command("keytabs")
def build_keytabs(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: Annotated[bool, typer.Option("--force", "-f", help="Re-extract keytabs that already exist (does not change principal keys)")] = False,
    realm_filter: Annotated[Optional[str], typer.Option("--realm", help="Only process this realm")] = None,
):
    """Generate Kerberos keytabs for hosts, and the KDC principal bundle.

    Host membership resolves through the roles already in the repo:

        host --(domain-<domain> role)--> domain --(realm.toml domains)--> realm

    so a host gets a keytab once its domain role lists it and some realm
    claims that domain.  Use 'aegis realm set <REALM> --add-domain <domain>'
    to declare the latter.

    Unlike --rotate on the SSH and Nexus builders, --force here is safe: it
    re-extracts a keytab from the principals already stored in the repo,
    leaving key material untouched.
    \b
    Examples:
        aegis build keytabs
        aegis build keytabs --force --realm SEA.FUDO.ORG    after a rekey
    """
    from . import host_secrets, realm as realm_mod
    from . import kerberos as krb
    import tempfile

    repo = get_secrets_repo(secrets_path)
    admin_keys = admin_recipients(repo)

    if not repo.realms_path().is_dir():
        typer.echo("No Kerberos realms configured in src/kerberos/realms/")
        typer.echo("Use 'aegis realm init <REALM>' to create a realm first.")
        return

    grouped = realm_mod.hosts_by_realm(repo)
    if realm_filter:
        grouped = {k: v for k, v in grouped.items() if k == realm_filter}

    if not grouped:
        typer.echo("No hosts resolved to a Kerberos realm.")
        typer.echo("")
        typer.echo("A host reaches a realm via its domain-<domain> role and the")
        typer.echo("realm's declared domains. Check both with:")
        typer.echo("  aegis realm list")
        typer.echo("  aegis check")
        return

    for realm_name in sorted(grouped):
        members = sorted(grouped[realm_name], key=lambda m: m.hostname)
        typer.echo(f"\nProcessing realm: {realm_name}")

        realm_config = realm_mod.load(repo, realm_name)

        if not repo.realm_path(realm_name).is_dir():
            typer.echo(f"  Realm directory not found: {repo.realm_path(realm_name)}")
            typer.echo(f"  Use 'aegis realm init {realm_name}' to initialize.")
            continue

        realm_key_enc = repo.realm_key_path(realm_name)
        if not realm_key_enc.exists():
            typer.echo(f"  Realm key not found: {realm_key_enc}")
            continue

        # The KDC role must exist *before* keytabs are built: a keytab
        # encrypted without the KDC as a recipient cannot be read by the KDC,
        # and re-running will not repair it (the file already exists).
        kdc_role_pubkey = None
        kdc_pub_path = repo.role_pubkey_path(realm_config.kdc_role)
        if kdc_pub_path.exists():
            kdc_role_pubkey = kdc_pub_path.read_text().strip()
        else:
            typer.secho(
                f"  Warning: role '{realm_config.kdc_role}' has no public key at "
                f"{kdc_pub_path}.\n"
                f"  Keytabs built now will NOT be readable by the KDC, and "
                f"re-running will not fix them.\n"
                f"  Create it first: aegis role init {realm_config.kdc_role}",
                fg=typer.colors.YELLOW,
            )

        if dry_run:
            typer.echo(f"  [dry-run] Would process {len(members)} hosts")
            for member in members:
                typer.echo(f"    - {member.hostname} ({member.fqdn})")
            continue

        with tempfile.TemporaryDirectory(prefix="aegis-krb-") as tmp:
            tmpdir = Path(tmp)
            realm_tmp = tmpdir / realm_name
            realm_tmp.mkdir()
            principals_tmp = realm_tmp / "principals"
            principals_tmp.mkdir()

            typer.echo(f"  Decrypting realm key...")
            realm_key_plain = realm_tmp / "realm.key"
            realm_key_plain.write_bytes(crypto.decrypt_age_bytes(realm_key_enc))

            principals_enc = repo.realm_principals_path(realm_name)
            if principals_enc.exists():
                principal_files = sorted(principals_enc.glob("*.age"))
                typer.echo(f"  Decrypting {len(principal_files)} principals...")
                for princ_file in principal_files:
                    princ_content = crypto.decrypt_age_bytes(princ_file)
                    (principals_tmp / f"{princ_file.stem}.key").write_bytes(princ_content)

            typer.echo(f"  Instantiating realm database...")
            try:
                kdc_conf = krb.instantiate_realm(
                    realm_name, realm_tmp, etypes=realm_config.etypes
                )
            except Exception as e:
                typer.echo(f"  Error instantiating realm: {e}", err=True)
                continue

            new_principals: list[Path] = []

            for member in members:
                hostname = member.hostname
                typer.echo(f"  Processing host: {hostname} ({member.fqdn})")

                try:
                    host_age_key = get_host_age_pubkey(hostname, repo)
                except AegisError as e:
                    typer.echo(f"    Skipping {hostname}: {e}", err=True)
                    continue

                host_config = repo.get_host_config(hostname)
                if not host_config:
                    typer.echo(f"    Error: No config found for {hostname}", err=True)
                    continue

                services = host_config.services

                missing = [
                    svc for svc in services
                    if not (principals_tmp / f"{svc}_{member.fqdn}.key").exists()
                ]
                if missing:
                    typer.echo(f"    Adding principals: {', '.join(missing)}")
                    try:
                        added = krb.add_host_to_realm(
                            member.fqdn,
                            krb.RealmConfig(realm_name, realm_key_plain, principals_tmp),
                            kdc_conf,
                            services=missing,
                        )
                        new_principals.extend(added)
                    except Exception as e:
                        typer.echo(f"    Error adding principals: {e}", err=True)
                        continue

                keytab_output = repo.host_deploy_path(hostname) / "keytab.age"
                if keytab_output.exists() and not force:
                    typer.echo(f"    Keytab exists (use --force to re-extract)")
                    # Still reconcile the manifest: skipping it here is how a
                    # host ends up with a keytab and no manifest entry.
                    _sync_keytab_manifest(repo, hostname)
                    continue

                typer.echo(f"    Extracting keytab...")
                keytab_tmp = tmpdir / f"{hostname}.keytab"
                try:
                    krb.extract_host_keytab(
                        member.fqdn, kdc_conf, keytab_tmp, services=services,
                    )
                except Exception as e:
                    typer.echo(f"    Error extracting keytab: {e}", err=True)
                    continue

                # A keytab can hold several kvnos for the same principal, so a
                # rotation in progress emits both: the service keeps working
                # with the key it already has until it receives this keytab.
                try:
                    carried = _append_retained_keys(
                        repo, realm_name, realm_config, realm_key_plain,
                        member, services, keytab_tmp, tmpdir,
                    )
                except Exception as e:
                    typer.echo(
                        f"    Error adding retained keys: {e}", err=True)
                    continue
                if carried:
                    typer.echo(
                        f"    Carrying pre-rekey keys for: {', '.join(carried)}")

                recipients = [host_age_key, *admin_keys]
                if kdc_role_pubkey:
                    recipients.append(kdc_role_pubkey)

                keytab_output.parent.mkdir(parents=True, exist_ok=True)
                crypto.encrypt_age(keytab_tmp.read_bytes(), recipients, keytab_output)
                typer.echo(f"    Wrote: {keytab_output}")

                _sync_keytab_manifest(repo, hostname)
                typer.echo(f"    Updated manifest")

            if new_principals:
                typer.echo(f"\n  Saving {len(new_principals)} new principals...")
                principals_enc.mkdir(parents=True, exist_ok=True)
                for princ_file in new_principals:
                    if not princ_file.exists():
                        continue
                    princ_out = principals_enc / f"{princ_file.stem}.age"
                    crypto.encrypt_age(princ_file.read_bytes(), admin_keys, princ_out)
                    typer.echo(f"    Saved: {princ_out.name}")

                    principal = realm_mod.principal_from_filename(
                        princ_file.stem, realm_config.principals)
                    if principal not in realm_config.principals:
                        entry = realm_mod.classify(principal, realm_name)
                        host_for = next(
                            (m.hostname for m in members
                             if principal.endswith(f"/{m.fqdn}")), None)
                        entry.host = host_for
                        realm_config.principals[principal] = entry
                realm_mod.save(repo, realm_config)

            typer.echo(f"\n  Generating KDC principals file...")
            all_principals = b"".join(
                f.read_bytes() for f in sorted(principals_tmp.glob("*.key"))
            )

            if all_principals and kdc_role_pubkey:
                kdc_principals_out = repo.kdc_deploy_path() / f"{realm_name}-principals.age"
                kdc_principals_out.parent.mkdir(parents=True, exist_ok=True)
                crypto.encrypt_age(
                    all_principals, [kdc_role_pubkey, *admin_keys], kdc_principals_out)
                typer.echo(f"  Wrote KDC principals: {kdc_principals_out}")

                # The KDC needs the realm master key to encrypt the database
                # it builds; a principal bundle alone is not enough.
                realm_key_out = (
                    repo.kdc_deploy_path() / f"{realm_name}-realm-key.age")
                crypto.encrypt_age(
                    realm_key_plain.read_bytes(),
                    [kdc_role_pubkey, *admin_keys],
                    realm_key_out,
                )
                typer.echo(f"  Wrote KDC realm key:   {realm_key_out}")

                _build_kdc_service_keytabs(
                    repo, realm_name, kdc_conf, principals_tmp,
                    kdc_role_pubkey, admin_keys, tmpdir,
                )
            elif not kdc_role_pubkey:
                typer.echo(f"  Skipped KDC principals file (no KDC role public key)")

    typer.secho("\nKeytab build complete!", fg=typer.colors.GREEN)


#: Service keytabs the KDC daemons themselves need, distinct from host/service
#: keytabs built for realm members above. Each maps the keytab's role to the
#: principal name variants that might hold it -- the first one present in the
#: realm's stored principals wins. ``kadmind`` is the one Heimdal always
#: creates via ``kadmin init``; ``kpasswdd`` varies by how the realm was
#: initialized (fudo's legacy tooling used ``kadmin/changepw``, stock Heimdal
#: uses ``changepw/kerberos``); ``hprop`` only exists for realms doing
#: KDC replication and is skipped silently when absent.
_KDC_SERVICE_KEYTABS: dict[str, tuple[str, ...]] = {
    "kadmind": ("kadmin/admin",),
    "kpasswdd": ("kadmin/changepw", "changepw/kerberos"),
    "hprop": ("kadmin/hprop",),
}


def _build_kdc_service_keytabs(
    repo: config.SecretsRepo,
    realm_name: str,
    kdc_conf: Path,
    principals_tmp: Path,
    kdc_role_pubkey: str,
    admin_keys: list[str],
    tmpdir: Path,
) -> None:
    """Extract keytabs for the KDC's own daemons: kadmind, kpasswdd, hprop.

    These are distinct from host/service keytabs: they authenticate the KDC's
    own admin/password/propagation daemons to clients, not a host to the KDC.
    Encrypted to the KDC role only -- no individual host holds these, so there
    is no host key in the recipient list, matching the principals/realm-key
    bundle above.
    """
    from . import kerberos as krb

    for service, candidates in _KDC_SERVICE_KEYTABS.items():
        principal = next(
            (p for p in candidates
             if (principals_tmp / f"{p.replace('/', '_')}@{realm_name}.key").exists()),
            None,
        )
        if principal is None:
            if service == "hprop":
                continue
            typer.secho(
                f"  Warning: no {'/'.join(candidates)}@{realm_name} principal "
                f"found -- {service} keytab not built. kadmind/kpasswdd will "
                f"not be able to start from this bundle.",
                fg=typer.colors.YELLOW,
            )
            continue

        keytab_tmp = tmpdir / f"{realm_name}-{service}.keytab"
        try:
            krb.extract_keytab(
                [f"{principal}@{realm_name}"], kdc_conf, keytab_tmp,
            )
        except Exception as e:
            typer.echo(f"  Error extracting {service} keytab: {e}", err=True)
            continue

        keytab_out = repo.kdc_deploy_path() / f"{realm_name}-{service}.keytab.age"
        keytab_out.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(
            keytab_tmp.read_bytes(), [kdc_role_pubkey, *admin_keys], keytab_out)
        typer.echo(f"  Wrote KDC {service} keytab: {keytab_out}")


def _append_retained_keys(
    repo: config.SecretsRepo,
    realm_name: str,
    realm_config,
    realm_key_plain: Path,
    member,
    services: list[str],
    keytab_path: Path,
    tmpdir: Path,
) -> list[str]:
    """Append any retained pre-rekey keys for this host to its keytab.

    `kadmin ext_keytab` appends rather than truncating, so extracting the old
    principals from a second throwaway database into the same file leaves the
    keytab holding both kvnos. That is what makes `realm rekey-principal` a
    graceful rotation instead of a hard cutover.

    Returns the principals whose old key was carried.
    """
    from . import kerberos as krb, realm as realm_mod

    previous_dir = repo.realm_previous_principals_path(realm_name)
    if not previous_dir.is_dir():
        return []

    # Only the services this host actually has: ext_keytab fails on a
    # principal the database does not contain.
    wanted = {}
    for service in services:
        principal = f"{service}/{member.fqdn}"
        stem = realm_mod.principal_filename(principal)
        source = previous_dir / f"{stem}.age"
        if source.exists():
            wanted[service] = (stem, source)

    if not wanted:
        return []

    prev_root = tmpdir / f"previous-{member.hostname}"
    prev_realm = prev_root / realm_name
    prev_principals = prev_realm / "principals"
    prev_principals.mkdir(parents=True, exist_ok=True)

    # The old database needs the realm key too, or it cannot be built.
    (prev_realm / "realm.key").write_bytes(realm_key_plain.read_bytes())
    for stem, source in wanted.values():
        (prev_principals / f"{stem}.key").write_bytes(
            crypto.decrypt_age_bytes(source))

    prev_conf = krb.instantiate_realm(
        realm_name, prev_realm, etypes=realm_config.etypes)

    krb.extract_host_keytab(
        member.fqdn, prev_conf, keytab_path, services=sorted(wanted),
    )

    return [f"{service}/{member.fqdn}" for service in sorted(wanted)]


def _sync_keytab_manifest(repo: config.SecretsRepo, hostname: str) -> None:
    """Ensure the host manifest describes its keytab, per src/ placement."""
    from . import host_secrets

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    manifest.keytab = host_secrets.make_keytab_entry(
        host_placement(repo, hostname, "keytab")
    )
    host_secrets.save_host_manifest(repo.deploy_path, manifest)


@build_app.command("user-secrets")
def build_user_secrets(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Process only this user"),
):
    """Collect and re-encrypt user secrets from user repos.
    
    User secrets are stored with privacy-preserving hashed filenames.
    A manifest file (manifest.age) is created for each user on each host,
    encrypted for both the host and the user, mapping hashed names to
    actual secret names and metadata.
    \b
    Example:
        aegis build user-secrets --user alice
    """
    import tempfile
    from . import manifest as mf
    
    repo = get_secrets_repo(secrets_path)

    admin_keys = admin_recipients(repo)

    # Get list of users to process
    if user:
        users = [user]
    else:
        users = repo.list_users()
    
    if not users:
        typer.echo("No users configured. Use 'aegis user add' first.")
        return
    
    for username in users:
        typer.echo(f"\nProcessing user: {username}")
        
        user_config = repo.get_user_config(username)
        if not user_config:
            typer.echo(f"  Warning: No config found for {username}", err=True)
            continue
        
        if not user_config.hosts:
            typer.echo(f"  No hosts configured for {username}, skipping")
            continue

        # Resolve the user's allowed-host set, expanding any "*" sentinel
        # against the current active hosts. Building per-host manifests
        # stops the moment a wildcard user reads on this set.
        allowed = repo.resolve_user_allowed_hosts(user_config)
        
        # Get user's public key for manifest encryption
        user_pubkey = user_config.public_key
        if not user_pubkey:
            # Try to read from file
            user_pubkey_path = repo.user_pubkey_path(username)
            if user_pubkey_path.exists():
                user_pubkey = user_pubkey_path.read_text().strip()
        
        if not user_pubkey:
            typer.echo(f"  Warning: No public key found for {username}", err=True)
            typer.echo(f"  Manifest will only be encrypted for hosts (not user)", err=True)
        
        # Find the user's private key (for decrypting their repo)
        user_key_path = repo.user_key_path(username)
        if not user_key_path.exists():
            typer.echo(f"  Warning: No private key found at {user_key_path}", err=True)
            continue
        
        # Find the user's repo
        # First check flake inputs, then fall back to repo_url
        user_repo_path = _find_user_repo(repo, username, user_config)
        if not user_repo_path:
            typer.echo(f"  Warning: Could not find repo for {username}", err=True)
            typer.echo(f"  Set repo_url in user config or add as flake input")
            continue
        
        typer.echo(f"  Repo: {user_repo_path}")
        
        if dry_run:
            typer.echo(
                f"  [dry-run] Would process secrets for hosts: "
                f"{', '.join(sorted(allowed))}"
            )
            continue
        
        # Decrypt user's private key
        typer.echo(f"  Decrypting user key...")
        try:
            user_private_key = crypto.decrypt_age(user_key_path)
        except Exception as e:
            typer.echo(f"  Error decrypting user key: {e}", err=True)
            continue
        
        # Get host public keys for re-encryption
        host_keys: dict[str, str] = {}
        for hostname in sorted(allowed):
            try:
                host_keys[hostname] = get_host_age_pubkey(hostname, repo)
            except AegisError as e:
                typer.echo(f"  Warning: skipping {hostname}: {e}", err=True)
            except Exception as e:
                typer.echo(f"  Warning: Could not get host {hostname}: {e}", err=True)
        
        if not host_keys:
            typer.echo(f"  No valid hosts found, skipping")
            continue
        
        # Create a manifest for each host (or load existing)
        host_manifests: dict[str, mf.Manifest] = {}
        for hostname in host_keys:
            manifest_path = repo.host_deploy_path(hostname) / "users" / username / "manifest.age"
            if manifest_path.exists():
                try:
                    host_manifests[hostname] = mf.load_manifest(
                        manifest_path,
                        lambda p: crypto.decrypt_age(p),
                    )
                except Exception:
                    # Can't decrypt existing manifest, start fresh
                    host_manifests[hostname] = mf.Manifest.empty()
            else:
                host_manifests[hostname] = mf.Manifest.empty()
        
        # Process environment variables
        env_dir = user_repo_path / "env"
        if env_dir.exists():
            env_secrets = _process_user_secrets_dir_with_manifest(
                env_dir, username, user_private_key, host_keys, 
                admin_keys, repo, "env", host_manifests,
            )
            typer.echo(f"  Processed {env_secrets} env vars")
        
        # Process files
        files_dir = user_repo_path / "files"
        if files_dir.exists():
            file_secrets = _process_user_secrets_dir_with_manifest(
                files_dir, username, user_private_key, host_keys,
                admin_keys, repo, "file", host_manifests,
            )
            typer.echo(f"  Processed {file_secrets} files")
        
        # Save manifests for each host (encrypted for host + user + admin)
        typer.echo(f"  Saving manifests...")
        for hostname, manifest in host_manifests.items():
            manifest_path = repo.host_deploy_path(hostname) / "users" / username / "manifest.age"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Recipients: host, user (if available), admin
            recipients = [host_keys[hostname], *admin_keys]
            if user_pubkey:
                recipients.append(user_pubkey)
            
            mf.save_manifest(manifest, manifest_path, crypto.encrypt_age, recipients)
            typer.echo(f"    {hostname}: {len(manifest.secrets)} secrets")
    
    typer.secho("\nUser secrets build complete!", fg=typer.colors.GREEN)


def _find_user_repo(repo: config.SecretsRepo, username: str, user_config: config.UserConfig) -> Optional[Path]:
    """Find the path to a user's secrets repo.
    
    Checks:
    1. Flake input path (if running from flake context)
    2. Sibling directory (aegis-secrets-<username>)
    3. repo_url in config (would need to clone)
    """
    # Check for sibling directory
    sibling = repo.path.parent / f"aegis-secrets-{username}"
    if sibling.exists():
        return sibling
    
    # Check for flake input (set via environment)
    import os
    flake_input = os.environ.get(f"AEGIS_USER_REPO_{username.upper()}")
    if flake_input:
        flake_path = Path(flake_input)
        if flake_path.exists():
            return flake_path
    
    # Check inputs directory (common flake structure)
    inputs_dir = repo.path / "inputs" / f"aegis-secrets-{username}"
    if inputs_dir.exists():
        return inputs_dir
    
    return None


def _process_user_secrets_dir_with_manifest(
    source_dir: Path,
    username: str,
    user_private_key: str,
    host_keys: dict[str, str],
    admin_keys: list[str],
    repo: config.SecretsRepo,
    secret_type: str,  # "env" or "file"
    host_manifests: dict,  # hostname -> Manifest
) -> int:
    """Process a directory of user secrets with privacy-preserving hashed filenames.
    
    Decrypts each .age file, updates the manifest with a hashed filename,
    and re-encrypts for each host using that hashed name.
    
    Returns number of secrets processed.
    """
    import tempfile
    from . import manifest as mf
    
    count = 0
    
    for secret_file in source_dir.glob("*.age"):
        secret_name = secret_file.stem  # Remove .age extension
        
        # Decrypt with user's key
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
                f.write(user_private_key)
                temp_key = Path(f.name)
            
            try:
                secret_content = crypto.decrypt_age(secret_file, identity_path=temp_key)
            finally:
                temp_key.unlink()
                
        except Exception as e:
            typer.echo(f"    Warning: Could not decrypt {secret_name}: {e}", err=True)
            continue
        
        # Re-encrypt for each host using hashed filename
        for hostname, host_key in host_keys.items():
            manifest = host_manifests[hostname]
            
            # Get or create hashed filename for this secret
            hashed_name = manifest.add_or_update(
                name=secret_name,
                secret_type=secret_type,
            )
            
            output_dir = repo.host_deploy_path(hostname) / "users" / username / "secrets"
            output_file = output_dir / f"{hashed_name}.age"
            
            output_dir.mkdir(parents=True, exist_ok=True)
            crypto.encrypt_age(secret_content, [host_key, *admin_keys], output_file)
        
        count += 1
    
    return count


@build_app.command("bundles")
def build_bundles(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
):
    """Package all secrets into host bundles."""
    typer.echo("build-bundles: Not yet implemented")
    # TODO: Create final host bundle structure


# =============================================================================
# aegis ssh import / nexus import / secret import / secret new
# =============================================================================

@ssh_app.command("import")
def import_ssh_host_keys(
    hostname: str = typer.Argument(..., help="Hostname to import keys for"),
    key_files: list[Path] = typer.Option([], "--key", help="Path to SSH private key file (type auto-detected, can specify multiple)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    target_dir: str = typer.Option("/run/aegis/ssh", "--target-dir", help="Target directory for SSH keys"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
    mode: str = typer.Option("0600", "--mode", help="Permissions for private key files"),
):
    """Import SSH host keys for OpenSSH server (NOT the master key).
    
    This imports the SSH keys that OpenSSH will use to identify the server
    to clients (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).
    
    These are NOT the master key! The master key is used to ENCRYPT these
    SSH host keys. The master key public should be set via 'set-master-key'.
    
    This command:
    - Auto-detects key type (ed25519, ecdsa, rsa)
    - Derives public keys automatically
    - Encrypts each private key separately as its own age file
    - Writes each public key as a plaintext .pub file alongside
    - Writes deployment metadata to secrets.toml for NixOS
    \b
    Example:
        aegis ssh import lambda \\
            --key /secure/lambda.ed25519.key \\
            --key /secure/lambda.ecdsa.key
    """
    from . import ssh_utils, host_secrets

    # Maps detected key_type string → SSH server filename stem
    KEY_TYPE_TO_STEM = {
        "ed25519": "ssh_host_ed25519_key",
        "ecdsa": "ssh_host_ecdsa_key",
        "rsa": "ssh_host_rsa_key",
    }

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not key_files:
        typer.echo("Error: At least one private key must be provided (use --key)", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing SSH host keys for {hostname}...")
    typer.echo(f"  (These are OpenSSH server keys, NOT the master key)")

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Ensure host config exists (create if missing)
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
        repo.set_host_config(host_config)
        typer.echo(f"  Created {repo.src_path / 'hosts' / f'{hostname}.toml'}")

    # Read and validate private keys, derive public keys
    try:
        keypairs = ssh_utils.read_ssh_keypairs(
            hostname=hostname,
            key_files=key_files,
        )
    except (FileNotFoundError, ValueError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    if not keypairs:
        typer.echo("Error: No valid keypairs found", err=True)
        raise typer.Exit(1)

    typer.echo(f"  Detected {len(keypairs)} keypair(s):")
    for kp in keypairs:
        typer.echo(f"    - {kp.key_type}")
        typer.echo(f"      Public key: {kp.public_key[:60]}...")

    # Encrypt each private key separately; write each public key plaintext
    admin_keys = admin_recipients(repo)
    recipients = [host_age_key, *admin_keys]

    ssh_dir = repo.host_deploy_path(hostname) / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)

    stems = []
    key_types = []
    for kp in keypairs:
        stem = KEY_TYPE_TO_STEM.get(kp.key_type, f"ssh_host_{kp.key_type}_key")
        age_path = ssh_dir / f"{stem}.age"
        pub_path = ssh_dir / f"{stem}.pub"
        crypto.encrypt_age(kp.private_key, recipients, age_path)
        pub_path.write_text(kp.public_key + "\n")
        stems.append(stem)
        key_types.append(kp.key_type)
        typer.echo(f"    Wrote {age_path.name} + {pub_path.name}")

    # Update manifest with one entry per private key
    record_placement(repo, hostname, "ssh-host-keys", config.Placement(
        target_dir=target_dir, user=user, group=group, mode=mode))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    placement = host_placement(repo, hostname, "ssh-host-keys")
    try:
        imported = host_secrets.make_ssh_host_keys_entries(
            stems=stems,
            placement=placement,
            key_types=key_types,
        )
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    # Correct any entry an earlier import misfiled before merging into it.
    # Deploy and initrd keys were swept into [[ssh-host-keys]] alongside the
    # real ones, which is where services.openssh.hostKeys comes from; moving
    # them to [secrets] keeps their target, so this is a change of declaration
    # only -- nothing on disk moves and no key is regenerated.
    existing, misfiled = host_secrets.split_ssh_host_keys(manifest.ssh_host_keys)
    if misfiled:
        manifest.secrets.update(host_secrets.make_ssh_auxiliary_entries(
            stems=[entry.target for entry in misfiled],
            placement=placement,
        ))
        typer.echo(
            f"  Moved {len(misfiled)} non-sshd key entr"
            f"{'y' if len(misfiled) == 1 else 'ies'} to [secrets]: "
            + ", ".join(entry.target for entry in misfiled)
        )

    # Merge rather than assign: importing one key per invocation is the obvious
    # way to drive this from a shell loop, and replacing the list makes each
    # run discard the previous one's declaration while leaving its ciphertext
    # in place -- a host that silently offers one key type.
    try:
        manifest.ssh_host_keys = host_secrets.merge_ssh_host_keys_entries(
            existing, imported)
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    manifest_path = host_secrets.save_host_manifest(repo.deploy_path, manifest)

    kept = len(manifest.ssh_host_keys) - len(imported)
    if kept > 0:
        typer.echo(f"  Kept {kept} existing key entr{'y' if kept == 1 else 'ies'}")

    typer.secho(f"\nSSH host keys imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output dir: {ssh_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Target: {target_dir}")
    typer.echo(f"  Encrypted for: {hostname} (master key) + admin")
    typer.echo(f"  These keys are for OpenSSH server identity.")


@nexus_app.command("import")
def import_nexus_key(
    hostname: str = typer.Argument(..., help="Hostname to import key for"),
    key_file: Path = typer.Option(..., "--file", help="Path to nexus HMAC key file"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    target: str = typer.Option("/run/aegis/nexus-key", "--target", help="Target path for nexus key"),
    user: str = typer.Option("root", "--user", help="Owner user"),
    group: str = typer.Option("root", "--group", help="Owner group"),
    mode: str = typer.Option("0400", "--mode", help="Permissions"),
):
    """Import a Nexus DDNS authentication key for a host.
    
    Imports an existing Nexus HMAC key. The key should be in the format:
    HmacSHA512:base64encodedkey
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    \b
    Example:
        aegis nexus import lambda --file /secure/lambda.nexus.hmac
    """
    from . import nexus

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not key_file.exists():
        typer.echo(f"Error: Key file not found: {key_file}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing Nexus key for {hostname}...")

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Ensure host config exists
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
        repo.set_host_config(host_config)
        typer.echo(f"  Created {repo.src_path / 'hosts' / f'{hostname}.toml'}")

    # Read and validate key
    key_content = key_file.read_text().strip()

    try:
        algo, encoded_key = nexus.read_key(key_file)
        typer.echo(f"  Algorithm: {algo}")
        typer.echo(f"  Key length: {len(encoded_key)} characters (base64)")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    # Get recipients
    admin_keys = admin_recipients(repo)
    recipients = [host_age_key, *admin_keys]
    
    # Encrypt and write
    output_path = repo.host_deploy_path(hostname) / "nexus-key.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(key_content, recipients, output_path)
    
    # Update manifest with deployment metadata
    from . import host_secrets
    record_placement(repo, hostname, "nexus-key", config.Placement(
        target=target, user=user, group=group, mode=mode))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    manifest.nexus_key = host_secrets.make_nexus_key_entry(
        host_placement(repo, hostname, "nexus-key")
    )
    manifest_path = host_secrets.save_host_manifest(repo.deploy_path, manifest)
    
    typer.secho(f"\nNexus key imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Target: {target}")
    typer.echo(f"  Encrypted for: {hostname} (host) + admin")


def print_secret_reference(
    name: str,
    target: str,
    roles: "list[str] | None" = None,
) -> None:
    """Print how to reach a secret from NixOS, right after creating it.

    The `secret-` prefix is the module's, not the operator's: a manifest entry
    written as [secrets.<name>] is published as `secret-<name>`, and a lookup
    without it misses silently -- the service is configured with nothing while
    Aegis goes on decrypting the secret perfectly well. Printing the reference
    at the point the secret is made is cheaper than rediscovering it.
    """
    from . import host_secrets

    key = host_secrets.manifest_key(name)
    unit = host_secrets.decrypt_unit(name)

    typer.echo("\nReference it in NixOS:")
    typer.echo(f'  config.aegis.secrets.manifest.targets."{key}"')
    typer.echo(f"    -> {target}")
    typer.echo("")
    typer.echo("  systemd.services.<yours> = {")
    typer.echo(f'    after    = [ "{unit}" ];')
    typer.echo(f'    requires = [ "{unit}" ];')
    typer.echo("  };")
    typer.echo("")
    typer.secho(
        f"  The 'secret-' prefix is the module's: [secrets.\"{name}\"] is "
        f"published as '{key}'.",
        fg=typer.colors.YELLOW,
    )
    if roles:
        typer.echo(
            f"  Decrypted in phase 2, with the "
            f"{' / '.join(roles)} key unwrapped in phase 1."
        )


@secret_app.command("import")
def import_secret(
    name: str = typer.Argument(..., help="Name of the secret; or, in the older two-argument form, the hostname"),
    legacy_name: Optional[str] = typer.Argument(None, help="Deprecated: 'aegis secret import HOST NAME' still works and means '--host HOST'", metavar="[NAME]"),
    file: Path = typer.Option(..., "--file", help="Path to secret file"),
    target: Optional[str] = typer.Option(None, "--target", help="Target path on each recipient host (e.g., /run/service/config)"),
    host: List[str] = typer.Option([], "--host", "-H", help="Recipient host (repeatable). Encrypted to that host's master key; a copy per host."),
    role: List[str] = typer.Option([], "--role", "-R", help="Recipient role (repeatable). Encrypted once to the role; every member host deploys it."),
    user: Optional[str] = typer.Option(None, "--user", help="Owner user on target host (default: root)"),
    group: Optional[str] = typer.Option(None, "--group", help="Owner group on target host (default: root)"),
    mode: Optional[str] = typer.Option(None, "--mode", help="File permissions, e.g. 0600 (default: 0400)"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing encrypted output for this name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Import an existing secret and encrypt it for hosts and/or roles.

    This is for service-specific or custom secrets that don't fit the standard
    categories (SSH, Nexus, Kerberos). The secret is encrypted and metadata
    about target path, ownership and permissions is stored in secrets.toml.
    \b
    Recipient selection (at least one is required; they may be combined):
      --host <h>  writes deploy/hosts/<h>/secrets/<name>.age, encrypted to
                  that host's master key plus the admin set.  One copy per
                  host, tied to the machine.
      --role <r>  writes deploy/roles/<r>/secrets/<name>.age -- ONE copy,
                  encrypted to the role's public key plus the admin set --
                  and points every member host's manifest at it.  Add a host
                  to the role later and it deploys the secret with no
                  re-import: 'aegis role add-host <r> <host>'.

    Prefer --role for anything that belongs to a *service* rather than to a
    machine, so that moving or scaling the service is a membership change.

    --target is required the first time; rotating with --force reuses the
    placement already recorded for the name unless you override it.
    \b
    Examples:
        aegis secret import my-service-token --host lambda \\
            --file /secure/lambda-service.token \\
            --target /run/myservice/token \\
            --user myservice --group myservice --mode 0600

        aegis secret import ldap-bind-password --role authentik \\
            --file /secure/authentik-ldap.password \\
            --target /run/authentik/ldap-password \\
            --user authentik --group authentik
    """
    from . import host_secrets

    # 'aegis secret import HOST NAME' predates recipient selection by option.
    # Two positionals can only be the old form, so translate it rather than
    # break every script and note where it went, as the renamed commands do.
    if legacy_name is not None:
        typer.secho(
            f"note: 'aegis secret import {name} {legacy_name}' is now "
            f"'aegis secret import {legacy_name} --host {name}'",
            fg=typer.colors.YELLOW,
            err=True,
        )
        host = [name, *host]
        name = legacy_name

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not host and not role:
        typer.echo(
            "Error: at least one --host or --role is required.\n"
            "  --host <h>  encrypts a copy for that machine\n"
            "  --role <r>  encrypts once for the role, so the secret follows "
            "the service between hosts",
            err=True,
        )
        raise typer.Exit(1)

    # Placement already on record is the answer for a rotation: --force with a
    # restated --target is how a target silently changes when the intent was
    # only to change the value.  Every recipient must agree on it, though, or
    # "the recorded one" is ambiguous.
    if target is None:
        recorded = {
            role_placement(repo, r, f"secret:{name}").target for r in role
        } | {
            host_placement(repo, h, f"secret:{name}").target for h in host
        }
        known = {t for t in recorded if t}
        if len(known) == 1 and None not in recorded:
            target = known.pop()
        else:
            typer.echo(
                "Error: --target is required"
                + (" (the recipients do not agree on a recorded one)"
                   if len(known) > 1 else "")
                + ".",
                err=True,
            )
            raise typer.Exit(1)

    if not file.exists():
        typer.echo(f"Error: Secret file not found: {file}", err=True)
        raise typer.Exit(1)

    # Validated up front, before anything is written: a run that encrypts for
    # two of three named recipients and then fails leaves the operator to work
    # out which half happened.
    for role_name in role:
        role_config = repo.get_role_config(role_name)
        if role_config is None:
            typer.echo(
                f"Error: role '{role_name}' is not configured. Run "
                f"'aegis role init {role_name}' first.",
                err=True,
            )
            raise typer.Exit(1)
        if not repo.role_pubkey_path(role_name).exists():
            typer.echo(
                f"Error: role '{role_name}' has no public key at "
                f"{repo.role_pubkey_path(role_name)}. "
                f"Re-run 'aegis role init {role_name}'.",
                err=True,
            )
            raise typer.Exit(1)

    outputs = (
        [repo.host_deploy_path(h) / "secrets" / f"{name}.age" for h in host]
        + [repo.role_secret_path(r, name) for r in role]
    )
    existing = [p for p in outputs if p.exists()]
    if existing and not force:
        typer.echo(
            f"Error: {name}.age already exists: "
            f"{', '.join(str(p) for p in existing)}.\n"
            f"Re-run with --force to overwrite (services using the old value "
            f"will see a different secret on next deploy).",
            err=True,
        )
        raise typer.Exit(1)

    # Read secret content as bytes: a p12, DER cert or keytab is not text.
    secret_content = file.read_bytes()
    admin_keys = admin_recipients(repo)
    placement = config.Placement(target=target, user=user, group=group, mode=mode)

    written: list[Path] = []

    for hostname in host:
        typer.echo(f"Importing secret '{name}' for host {hostname}...")

        host_age_key = get_host_age_pubkey(hostname, repo)
        ensure_host_config(repo, hostname)

        output_path = repo.host_deploy_path(hostname) / "secrets" / f"{name}.age"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(secret_content, [host_age_key, *admin_keys], output_path)
        written.append(output_path)

        record_placement(repo, hostname, f"secret:{name}", placement)

        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        manifest.secrets[name] = host_secrets.make_secret_entry(
            name=name,
            placement=host_placement(repo, hostname, f"secret:{name}"),
        )
        host_secrets.save_host_manifest(repo.deploy_path, manifest)

    for role_name in role:
        typer.echo(f"Importing secret '{name}' for role {role_name}...")

        role_pubkey = repo.role_pubkey_path(role_name).read_text().strip()
        output_path = repo.role_secret_path(role_name, name)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(secret_content, [role_pubkey, *admin_keys], output_path)
        written.append(output_path)

        # Placement belongs to the role, not to today's members: a host added
        # tomorrow has to land the secret in the same place without anybody
        # remembering to say so.
        record_role_placement(repo, role_name, f"secret:{name}", placement)

        members = reconcile_role_members(repo, role_name)
        role_config = repo.get_role_config(role_name)
        assert role_config is not None
        if not role_config.hosts:
            typer.secho(
                f"  Note: role '{role_name}' has no members yet, so nothing "
                f"deploys this secret.",
                fg=typer.colors.YELLOW,
            )
            typer.echo(f"  Grant it: aegis role add-host {role_name} <host>")
        else:
            typer.echo(f"  Members updated: {', '.join(members) or '(none deploying)'}")

    # Reported as resolved, not as typed: with the defaults falling back to
    # whatever was already recorded, the flags do not say where it lands.
    resolved = (
        role_placement(repo, role[0], f"secret:{name}") if role
        else host_placement(repo, host[0], f"secret:{name}")
    )
    defaults = host_secrets.DEFAULTS["secret"]

    typer.secho(f"\nSecret imported successfully!", fg=typer.colors.GREEN)
    for path in written:
        typer.echo(f"  Output: {path}")
    typer.echo(f"  Target: {resolved.target or target}")
    typer.echo(
        f"  Owner: {resolved.user or defaults['user']}:"
        f"{resolved.group or defaults['group']}")
    typer.echo(f"  Mode: {resolved.mode or defaults['mode']}")
    if role:
        typer.echo(f"  Roles: {', '.join(role)}")

    print_secret_reference(name, resolved.target or target, list(role))


@secret_app.command("new")
def new_secret(
    # Rich reads square brackets as markup, so the extra_secrets key is
    # spelled out in the docstring instead of here.
    name: str = typer.Argument(..., help="Secret name; also its key under extra_secrets in src/"),
    host: List[str] = typer.Option([], "--host", "-H", help="Recipient host (repeatable). Each host gets its own .age file encrypted to that host's master key."),
    role: List[str] = typer.Option([], "--role", "-R", help="Recipient role (repeatable). The secret is encrypted for every current member of the role."),
    target: str = typer.Option(..., "--target", help="Target path on each recipient host, e.g. /run/<service>/<file>"),
    user: str = typer.Option("root", "--user", help="Owner user on target host (default: root)"),
    group: str = typer.Option("root", "--group", help="Owner group on target host (default: root)"),
    mode: str = typer.Option("0400", "--mode", help="File permissions on target host (default: 0400)"),
    length: int = typer.Option(32, "--length", help="Length in characters (encoded formats) or bytes (--format raw) (default: 32)"),
    fmt: str = typer.Option("hex", "--format", help="hex | base64 | base64url | alphanumeric | raw (default: hex)"),
    charset: Optional[str] = typer.Option(None, "--charset", help="Alphabet for --format=alphanumeric. A literal string, or one of: " + ", ".join(crypto.ALPHABET_PRESETS.keys())),
    force: bool = typer.Option(False, "--force", help="Overwrite existing encrypted outputs (DESTRUCTIVE: services reading the old value will lose access)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Generate a fresh random secret and encrypt it for one or more recipients.

    Equivalent to: openssl rand + 'aegis secret import' for each recipient,
    with the plaintext never touching the filesystem. The same plaintext is
    encrypted once per recipient host; each gets its own .age file. NAME is
    also the key it takes under 'extra_secrets' in src/.
    \b
    Recipient selection (at least one is required; they may be combined):
      --host <h>  encrypts to that host's master key plus the admin set, at
                  deploy/hosts/<h>/secrets/<name>.age. One copy per host.
      --role <r>  encrypts ONCE, to the role's public key plus the admin set,
                  at deploy/roles/<r>/secrets/<name>.age, and points every
                  member's manifest at it -- so a host added later by
                  'aegis role add-host' decrypts it on next deploy, with no
                  rebuild and no access to the plaintext.

    Prefer --role for a secret that belongs to a service rather than to a
    machine: moving or scaling the service is then a membership change.

    The plaintext is not printed; 'aegis verify <host>' is how you confirm a
    host can decrypt. Rotation means re-invoking with --force, then restarting
    whatever service still holds the old value.
    \b
    Examples:
        aegis secret new aurelius-ingest-token \\
            --host aedile --host nostromo --host fimbria \\
            --target /run/aurelius/token \\
            --user aurelius --group aurelius --mode 0400

        aegis secret new dns-key-signing-secret \\
            --role dns-master-fudo.org \\
            --target /run/nsd/signing.key
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not host and not role:
        typer.echo(
            "Error: at least one --host or --role is required.",
            err=True,
        )
        raise typer.Exit(1)

    # Validate every named role exists. We do NOT auto-create roles here: a
    # role that has no keypair cannot be an encryption target, and silently
    # minting one would mean the user encrypts for an identity they did not
    # intend to create.
    role_pubkeys: dict[str, str] = {}
    for r in role:
        role_cfg = repo.get_role_config(r)
        if role_cfg is None:
            typer.echo(
                f"Error: role '{r}' is not configured. Run "
                f"'aegis role init {r}' first.",
                err=True,
            )
            raise typer.Exit(1)
        role_pub_path = repo.role_pubkey_path(r)
        if not role_pub_path.exists():
            typer.echo(
                f"Error: role '{r}' has no public key at {role_pub_path}. "
                f"Re-run 'aegis role init {r}'.",
                err=True,
            )
            raise typer.Exit(1)
        role_pubkeys[r] = role_pub_path.read_text().strip()

    for h in host:
        host_cfg = repo.get_host_config(h)
        if not host_cfg:
            typer.echo(
                f"Error: host '{h}' is not initialised; run "
                f"'aegis host add {h}' first.",
                err=True,
            )
            raise typer.Exit(1)

    # Nothing is written until every output is known to be safe to write, so a
    # partial run cannot leave half the recipients on a new secret and half on
    # the old one.
    outputs = (
        [repo.host_deploy_path(h) / "secrets" / f"{name}.age" for h in host]
        + [repo.role_secret_path(r, name) for r in role]
    )
    existing = [p for p in outputs if p.exists()]
    if existing and not force:
        typer.echo(
            f"Error: {name}.age already exists: "
            f"{', '.join(str(p) for p in existing)}.\n"
            f"Re-run with --force to overwrite (services using the old value "
            f"will see a different secret on next deploy).",
            err=True,
        )
        raise typer.Exit(1)

    if charset and charset in crypto.ALPHABET_PRESETS and fmt == "alphanumeric":
        charset = crypto.ALPHABET_PRESETS[charset]

    # Once, off-disk.
    plaintext = crypto.generate_secret(format=fmt, length=length, charset=charset)

    typer.echo(
        f"Generating secret '{name}' for {len(host)} host(s) "
        f"and {len(role)} role(s) [format={fmt}, length={length}]..."
    )

    admin_keys = admin_recipients(repo)
    placement = config.Placement(target=target, user=user, group=group, mode=mode)

    for h in host:
        host_age_key = get_host_age_pubkey(h, repo)

        out = repo.host_deploy_path(h) / "secrets" / f"{name}.age"
        out.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(plaintext, [host_age_key, *admin_keys], out)

        record_placement(repo, h, f"secret:{name}", placement)

        manifest = host_secrets.load_host_manifest(repo.deploy_path, h)
        manifest.secrets[name] = host_secrets.make_secret_entry(
            name=name,
            placement=host_placement(repo, h, f"secret:{name}"),
        )
        host_secrets.save_host_manifest(repo.deploy_path, manifest)

    for r in role:
        out = repo.role_secret_path(r, name)
        out.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(plaintext, [role_pubkeys[r], *admin_keys], out)

        record_role_placement(repo, r, f"secret:{name}", placement)
        members = reconcile_role_members(repo, r)

        if not members:
            typer.secho(
                f"  Note: role '{r}' has no members that Aegis deploys to, so "
                f"nothing carries this secret yet.",
                fg=typer.colors.YELLOW,
            )
            typer.echo(f"  Grant it: aegis role add-host {r} <host>")

    recipients_desc = ", ".join(
        [f"host {h}" for h in host] + [f"role {r}" for r in role])
    typer.secho(
        f"\nSecret '{name}' written for: {recipients_desc}",
        fg=typer.colors.GREEN,
    )
    typer.echo(f"  Format        : {fmt} ({length})")
    typer.echo(f"  Target path   : {target}")
    typer.echo(f"  Owner / mode  : {user}:{group} / {mode}")
    typer.echo(
        "  Plaintext was not written to disk; verify decryption with "
        "`aegis verify <host>`."
    )

    print_secret_reference(name, target, list(role))


# =============================================================================
# aegis dnssec ...
# =============================================================================

def _ensure_dns_role(
    repo: config.SecretsRepo,
    domain: str,
    hostname: str,
) -> str:
    """Ensure dns-master-<domain> role exists, create if needed.

    Returns the role's public key.
    """
    role_name = f"dns-master-{domain}"
    existing = repo.get_role_config(role_name)

    if existing:
        role_pub_path = repo.role_pubkey_path(role_name)
        if not role_pub_path.exists():
            typer.echo(f"Error: Role {role_name} exists but public key not found", err=True)
            raise typer.Exit(1)
        if hostname not in existing.hosts:
            typer.echo(f"  Adding {hostname} to role {role_name}...")
            _add_host_to_role_impl(repo, role_name, hostname)
        return role_pub_path.read_text().strip()

    # Create the role
    typer.echo(f"Creating role: {role_name}")

    host_age_key = get_host_age_pubkey(hostname, repo)
    keypair = crypto.generate_age_keypair()
    admin_keys = admin_recipients(repo)

    # Store role private key encrypted for admin only
    role_key_path = repo.role_key_path(role_name)
    role_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, admin_keys, role_key_path)

    # Save public key
    role_pub_path = repo.role_pubkey_path(role_name)
    role_pub_path.parent.mkdir(parents=True, exist_ok=True)
    role_pub_path.write_text(keypair.public_key)

    # Create per-host role key
    host_role_path = repo.host_role_key_path(hostname, role_name)
    host_role_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, [host_age_key, *admin_keys], host_role_path)

    # Save role config
    role_config = config.RoleConfig(name=role_name, hosts=[hostname])
    repo.set_role_config(role_config)

    return keypair.public_key


def _add_host_to_role_impl(
    repo: config.SecretsRepo,
    role_name: str,
    hostname: str,
    role_privkey: str | None = None,
) -> None:
    """Decrypt the role private key (if needed) and encrypt it for hostname."""
    if role_privkey is None:
        role_key_path = repo.role_key_path(role_name)
        try:
            role_privkey = crypto.decrypt_age(role_key_path)
        except Exception as e:
            typer.echo(f"Error decrypting role key {role_name}: {e}", err=True)
            raise typer.Exit(1)

    host_age_key = get_host_age_pubkey(hostname, repo)
    admin_keys = admin_recipients(repo)

    out_path = repo.host_role_key_path(hostname, role_name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(role_privkey, [host_age_key, *admin_keys], out_path)

    role_config = repo.get_role_config(role_name)
    if role_config and hostname not in role_config.hosts:
        role_config.hosts.append(hostname)
        repo.set_role_config(role_config)


@dnssec_app.command("generate")
def generate_dnssec_keys(
    domain: str = typer.Argument(..., help="Domain name (e.g., fudo.org)"),
    hostname: str = typer.Option(..., "--host", "-h", help="DNS master server hostname"),
    algorithm: str = typer.Option("ECDSAP256SHA256", "--algorithm", "-a", help="DNSSEC algorithm"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing keys"),
    target_dir: Optional[str] = typer.Option(None, "--target-dir", help="Target directory for keys (default: /var/lib/dnssec/<domain>)"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
):
    """Generate DNSSEC Key Signing Key (KSK) for a domain.
    
    Creates a new DNSSEC KSK using ldns-keygen and encrypts it for the
    dns-master-<domain> role (auto-created if needed) and the admin.
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    
    Requires ldns-keygen to be available in PATH.
    \b
    Example:
        aegis dnssec generate fudo.org --host polaris
        aegis dnssec generate fudo.org --host polaris --algorithm ED25519
    """
    from . import dnssec
    import tempfile
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    # Check if keys already exist
    existing = repo.get_dnssec_config(domain)
    if existing and not force:
        typer.echo(f"DNSSEC keys already exist for {domain} (keytag: {existing.keytag})")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Validate algorithm
    if algorithm not in dnssec.ALGORITHM_MAP:
        typer.echo(f"Error: Unknown algorithm: {algorithm}", err=True)
        typer.echo(f"Valid options: {', '.join(dnssec.ALGORITHM_MAP.keys())}")
        raise typer.Exit(1)
    
    typer.echo(f"Generating DNSSEC KSK for {domain}...")
    typer.echo(f"  Algorithm: {algorithm} ({dnssec.ALGORITHM_MAP[algorithm]})")
    
    # Ensure role exists and get its public key
    role_pubkey = _ensure_dns_role(repo, domain, hostname)
    admin_keys = admin_recipients(repo)
    recipients = [role_pubkey, *admin_keys]

    # Generate keys in temp directory
    with tempfile.TemporaryDirectory(prefix="aegis-dnssec-") as tmpdir:
        tmpdir = Path(tmpdir)
        
        try:
            key_files = dnssec.generate_ksk(domain, tmpdir, algorithm)
        except FileNotFoundError:
            typer.echo("Error: ldns-keygen not found in PATH", err=True)
            typer.echo("Install with: nix-shell -p ldns.examples")
            raise typer.Exit(1)
        except Exception as e:
            typer.echo(f"Error generating keys: {e}", err=True)
            raise typer.Exit(1)
        
        typer.echo(f"  Generated: {key_files.basename}")
        typer.echo(f"  Key tag: {key_files.keytag}")
        
        # Create output directory
        build_dir = repo.dnssec_build_path(domain)
        build_dir.mkdir(parents=True, exist_ok=True)
        
        # Encrypt and store keys
        typer.echo(f"Encrypting keys for: admin, dns-master-{domain}")
        
        # Public key (.key)
        key_content = key_files.key_file.read_text()
        crypto.encrypt_age(key_content, recipients, build_dir / "ksk.key.age")
        typer.echo(f"  ksk.key.age")
        
        # Private key (.private)
        private_content = key_files.private_file.read_text()
        crypto.encrypt_age(private_content, recipients, build_dir / "ksk.private.age")
        typer.echo(f"  ksk.private.age")
        
        # DS record (.ds)
        if key_files.ds_file.exists():
            ds_content = key_files.ds_file.read_text()
            crypto.encrypt_age(ds_content, recipients, build_dir / "ksk.ds.age")
            typer.echo(f"  ksk.ds.age")
            ds_record = ds_content.strip()
        else:
            ds_record = None
    
    # Save config (legacy - still keep for backward compat)
    dnssec_config = config.DnssecConfig(
        domain=domain,
        algorithm=algorithm,
        algorithm_num=dnssec.ALGORITHM_MAP[algorithm],
        keytag=key_files.keytag,
    )
    repo.set_dnssec_config(dnssec_config)
    
    # Save secrets manifest with deployment metadata
    from . import host_secrets
    dnssec_manifest = host_secrets.make_dnssec_entry(
        domain=domain,
        algorithm=algorithm,
        algorithm_num=dnssec.ALGORITHM_MAP[algorithm],
        keytag=key_files.keytag,
        target_dir=target_dir,
        user=user,
        group=group,
    )
    manifest_path = host_secrets.save_dnssec_manifest(repo.deploy_path, dnssec_manifest)
    
    typer.secho(f"\nDNSSEC keys generated successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {build_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Algorithm: {algorithm} ({dnssec.ALGORITHM_MAP[algorithm]})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    if dnssec_manifest.public_key:
        typer.echo(f"  Target dir: {dnssec_manifest.public_key.target.rsplit('/', 1)[0]}")
    
    if ds_record:
        typer.echo(f"\nDS Record (submit to registrar):")
        typer.echo(f"  {ds_record}")


@dnssec_app.command("import")
def import_dnssec_keys(
    domain: str = typer.Argument(..., help="Domain name (e.g., fudo.org)"),
    keys_dir: Path = typer.Option(..., "--keys-dir", "-k", help="Directory containing DNSSEC key files"),
    hostname: str = typer.Option(..., "--host", "-h", help="DNS master server hostname"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing keys"),
    target_dir: Optional[str] = typer.Option(None, "--target-dir", help="Target directory for keys (default: /var/lib/dnssec/<domain>)"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
):
    """Import existing DNSSEC Key Signing Key (KSK) for a domain.
    
    Imports DNSSEC key files generated by ldns-keygen:
      - K<domain>.+<alg>+<keytag>.key      (public key)
      - K<domain>.+<alg>+<keytag>.private  (private key)
      - K<domain>.+<alg>+<keytag>.ds       (DS record, optional)
    
    The keys are encrypted for the dns-master-<domain> role (auto-created
    if needed) and the admin.
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    \b
    Example:
        aegis dnssec import fudo.org --keys-dir /secrets/dnssec/fudo.org/ --host polaris
    """
    from . import dnssec
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    if not keys_dir.exists() or not keys_dir.is_dir():
        typer.echo(f"Error: Keys directory not found: {keys_dir}", err=True)
        raise typer.Exit(1)
    
    # Check if keys already exist
    existing = repo.get_dnssec_config(domain)
    if existing and not force:
        typer.echo(f"DNSSEC keys already exist for {domain} (keytag: {existing.keytag})")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Find key files
    key_files = dnssec.find_dnssec_keys(keys_dir, domain)
    if key_files is None:
        typer.echo(f"Error: No DNSSEC key files found for {domain} in {keys_dir}", err=True)
        typer.echo(f"Looking for files matching: K{domain}.+<alg>+<keytag>.*")
        raise typer.Exit(1)
    
    typer.echo(f"Importing DNSSEC keys for {domain}...")
    typer.echo(f"  Found: {key_files.basename}")
    typer.echo(f"  Algorithm: {key_files.algorithm} ({key_files.algorithm_num})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    
    # Check required files exist
    if not key_files.key_file.exists():
        typer.echo(f"Error: Public key file not found: {key_files.key_file}", err=True)
        raise typer.Exit(1)
    if not key_files.private_file.exists():
        typer.echo(f"Error: Private key file not found: {key_files.private_file}", err=True)
        raise typer.Exit(1)
    
    # Ensure role exists and get its public key
    role_pubkey = _ensure_dns_role(repo, domain, hostname)
    admin_keys = admin_recipients(repo)
    recipients = [role_pubkey, *admin_keys]

    # Create output directory
    build_dir = repo.dnssec_build_path(domain)
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # Encrypt and store keys
    typer.echo(f"Encrypting keys for: admin, dns-master-{domain}")
    
    # Public key (.key)
    key_content = key_files.key_file.read_text()
    crypto.encrypt_age(key_content, recipients, build_dir / "ksk.key.age")
    typer.echo(f"  ksk.key.age")
    
    # Private key (.private)
    private_content = key_files.private_file.read_text()
    crypto.encrypt_age(private_content, recipients, build_dir / "ksk.private.age")
    typer.echo(f"  ksk.private.age")
    
    # DS record (.ds) - optional
    ds_record = None
    if key_files.ds_file.exists():
        ds_content = key_files.ds_file.read_text()
        crypto.encrypt_age(ds_content, recipients, build_dir / "ksk.ds.age")
        typer.echo(f"  ksk.ds.age")
        ds_record = ds_content.strip()
    else:
        typer.echo(f"  (no DS record file found)")
    
    # Save config (legacy - still keep for backward compat)
    dnssec_config = config.DnssecConfig(
        domain=domain,
        algorithm=key_files.algorithm,
        algorithm_num=key_files.algorithm_num,
        keytag=key_files.keytag,
    )
    repo.set_dnssec_config(dnssec_config)
    
    # Save secrets manifest with deployment metadata
    from . import host_secrets
    dnssec_manifest = host_secrets.make_dnssec_entry(
        domain=domain,
        algorithm=key_files.algorithm,
        algorithm_num=key_files.algorithm_num,
        keytag=key_files.keytag,
        target_dir=target_dir,
        user=user,
        group=group,
    )
    manifest_path = host_secrets.save_dnssec_manifest(repo.deploy_path, dnssec_manifest)
    
    typer.secho(f"\nDNSSEC keys imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {build_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Algorithm: {key_files.algorithm} ({key_files.algorithm_num})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    if dnssec_manifest.public_key:
        typer.echo(f"  Target dir: {dnssec_manifest.public_key.target.rsplit('/', 1)[0]}")
    
    if ds_record:
        typer.echo(f"\nDS Record (submit to registrar):")
        typer.echo(f"  {ds_record}")


# =============================================================================
# aegis host ... / aegis user add
# =============================================================================


@host_app.command("add")
def init_host(
    hostname: str = typer.Argument(..., help="Hostname to initialize"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="DNS domain (e.g. sea.fudo.org); adds the host to the domain-<domain> role"),
    services: str = typer.Option("host,ssh", "--services", help="Comma-separated Kerberos services"),
):
    """Add a host to the secrets configuration.

    This initializes a host in the aegis-secrets repository. When you run
    'aegis build', the following will be generated for this host:
    - SSH host keys (ed25519, ecdsa, rsa)
    - Nexus DDNS authentication key
    - Kerberos keytabs (if the host's domain is claimed by a realm)

    Domain membership is recorded as membership in the 'domain-<domain>' role
    rather than as a field on the host, so there is exactly one place that
    answers "which hosts are in this domain".

    A host is only usable once it is declared, has a master key, and has been
    built for:
    \b
    Examples:
        aegis host add rama --domain sea.fudo.org
        aegis host set-key rama --public-key age1...
        aegis build
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    existing = repo.get_host_config(hostname)
    if existing:
        typer.echo(f"Host {hostname} already configured")
        raise typer.Exit(1)

    service_list = [s.strip() for s in services.split(",")]

    host_config = config.HostConfig(
        hostname=hostname,
        services=service_list,
    )
    repo.set_host_config(host_config)

    typer.secho(f"Initialized host: {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Services: {', '.join(service_list)}")
    typer.echo(f"  Config: {repo.src_path / 'hosts' / f'{hostname}.toml'}")

    if domain:
        from . import realm as realm_mod

        role_name = f"{realm_mod.DOMAIN_ROLE_PREFIX}{domain}"
        role_config = repo.get_role_config(role_name)
        if role_config is None:
            typer.echo(f"  Domain: {domain} (role {role_name} does not exist yet)")
            typer.echo(f"    Create it with: aegis role init {role_name}")
        else:
            if hostname not in role_config.hosts:
                role_config.hosts = sorted(role_config.hosts + [hostname])
                repo.set_role_config(role_config)
            typer.echo(f"  Domain: {domain} (added to role {role_name})")
            typer.echo(f"    Grant the key with: aegis role add-host {role_name} {hostname}")

    typer.echo("")
    typer.echo("Next:")
    typer.echo(f"  1. Set master key: aegis host set-key {hostname} --public-key 'age1...'")
    typer.echo("  2. Build secrets:  aegis build")


@host_app.command("set-key")
def set_master_key(
    hostname: str = typer.Argument(..., help="Hostname to set master key for"),
    public_key: str = typer.Option(..., "--public-key", "-k", help="age public key (e.g., 'age1...')"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Set the age public key for a host.

    The master key is used to ENCRYPT secrets for this host. The host must have
    the corresponding age private key to decrypt secrets at boot time.

    This is NOT an SSH host key for OpenSSH! This is the age key Aegis uses to
    encrypt secrets that only this host can decrypt.

    The public key should be in age format: "age1..."

    Typical setup:
    1. Host has age private key at /state/master-key/key (persistent storage)
    2. Extract the public key: age-keygen -y /state/master-key/key
    3. Set it here: aegis host set-key lambda --public-key "age1..."
    \b
    Example:
        aegis host set-key lambda --public-key "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    # Validate the public key format
    public_key = public_key.strip()
    if not public_key.startswith("age1"):
        typer.echo("Error: Public key must be in age format", err=True)
        typer.echo("  Expected: age1... (obtain with: age-keygen -y /path/to/key)", err=True)
        raise typer.Exit(1)

    # Get or create host config
    host_config = repo.get_host_config(hostname)
    replaced = host_config.age_pubkey if host_config else None
    if not host_config:
        typer.echo(f"Creating new host config for {hostname}...")
        host_config = config.HostConfig(
            hostname=hostname,
            age_pubkey=public_key,
        )
    else:
        host_config.age_pubkey = public_key

    repo.set_host_config(host_config)

    typer.secho(f"Master key set for {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Age public key: {public_key}")
    typer.echo(f"  Config: {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    typer.echo("")

    if replaced and replaced != public_key:
        # Existing files are still encrypted to the old key, and a plain
        # reencrypt will not notice: the recipient count is unchanged, which is
        # all age lets us compare.  Without --force the host silently fails to
        # decrypt anything at next boot.
        typer.secho(
            f"{hostname}'s previous master key was replaced, so its existing "
            f"secrets are still encrypted for the old key.",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  Replaced: {replaced}")
        typer.echo(f"  Rewrite them: aegis reencrypt --host {hostname} --force")
        typer.echo("")

    typer.echo("Now you can encrypt secrets for this host with 'aegis build'")

    if not host_config.deploys:
        typer.secho(
            f"Note: {hostname} has status '{host_config.status}', so nothing "
            f"will be built for it until that changes.",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  aegis host set-status {hostname} active")


@host_app.command("set-status")
def set_host_status(
    hostname: str = typer.Argument(..., help="Hostname"),
    status: str = typer.Argument(
        ...,
        help="One of: " + ", ".join(config.HOST_STATUSES),
    ),
    note: Optional[str] = typer.Option(
        None, "--note", "-n", help="Why, recorded alongside the status"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Record whether Aegis manages a host, and why not if it doesn't.

    Not every host in the repo is a machine waiting for secrets.  Without a
    way to say so, "no master key" can only be read as "broken", and the
    permanent errors that produces are what teaches you to stop reading
    'aegis check' output.
    \b
    active    fully managed; the default
    pending   declared but not yet initialised -- reserves the name so roles
              and realms can refer to it before it exists
    retired   decommissioned; must hold nothing, and whatever it once held
              should be treated as disclosed
    external  a real host Aegis does not deliver to -- a container served by
              its parent, or a machine someone else manages

    Only 'active' hosts are built for or encrypted to.
    \b
    Example:
        aegis host set-status pselby-work retired --note "laptop returned"
    """
    repo = get_secrets_repo(secrets_path)

    if status not in config.HOST_STATUSES:
        typer.echo(
            f"Error: unknown status {status!r}. Expected one of: "
            f"{', '.join(config.HOST_STATUSES)}",
            err=True,
        )
        raise typer.Exit(1)

    host_config = repo.get_host_config(hostname)
    if not host_config:
        host_config = config.HostConfig(hostname=hostname)
        typer.echo(f"Creating new host config for {hostname}...")

    previous = host_config.status
    host_config.status = status
    if note is not None:
        host_config.note = note
    repo.set_host_config(host_config)

    typer.secho(f"{hostname}: {previous} -> {status}", fg=typer.colors.GREEN)
    if host_config.note:
        typer.echo(f"  {host_config.note}")

    # Changing the status does not itself remove anything; say so rather than
    # letting the green line imply the host has been cleaned up.
    deploy = repo.host_deploy_path(hostname)
    stale = sorted(deploy.rglob("*.age")) if deploy.is_dir() else []
    if stale and not host_config.deploys:
        typer.secho(
            f"\n{len(stale)} encrypted file(s) are still deployed to {hostname}. "
            f"Nothing was removed.",
            fg=typer.colors.YELLOW,
        )
        typer.echo(f"  rm -r {deploy}")
        if status == config.STATUS_RETIRED and host_config.age_pubkey:
            typer.secho(
                "  Its key can still decrypt every copy it already has; treat "
                "those secrets as disclosed and rotate them.",
                fg=typer.colors.YELLOW,
            )


@user_app.command("add")
def add_user(
    username: str = typer.Argument(..., help="Username"),
    hosts: str = typer.Option(
        ...,
        "--hosts", "-h",
        help=(
            "Comma-separated list of hosts user can access. Pass '*' to grant "
            "access to every active host aegis manages now and in the future. "
            "An explicit host alongside '*' is redundant but harmless."
        ),
    ),
    repo_url: Optional[str] = typer.Option(None, "--repo-url", help="URL of user's secrets repo"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Add a user and generate their keypair.

    The public key is printed for the user to put in their own secrets repo;
    'aegis build user-secrets' then collects what they encrypt with it.
    \b
    Example:
        aegis user add alice --hosts rama,lambda
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    existing = repo.get_user_config(username)
    if existing:
        typer.echo(f"User {username} already configured")
        raise typer.Exit(1)
    
    host_list = [h.strip() for h in hosts.split(",")]
    
    # Generate keypair for user
    typer.echo(f"Generating keypair for {username}...")
    keypair = crypto.generate_age_keypair()
    
    # Encrypt private key for admin
    admin_keys = admin_recipients(repo)
    user_key_path = repo.user_key_path(username)
    user_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, admin_keys, user_key_path)
    
    # Save public key (for manifest encryption)
    user_pubkey_path = repo.user_pubkey_path(username)
    user_pubkey_path.write_text(keypair.public_key + "\n")
    
    # Save user config (including public key for convenience)
    user_config = config.UserConfig(
        username=username,
        hosts=host_list,
        repo_url=repo_url,
        public_key=keypair.public_key,
    )
    repo.set_user_config(user_config)
    
    typer.secho(f"Added user: {username}", fg=typer.colors.GREEN)
    typer.echo(f"  Hosts: {', '.join(host_list)}")
    typer.echo(f"  Private key: {user_key_path}")
    typer.echo(f"  Public key: {user_pubkey_path}")
    typer.echo("")
    typer.secho("Give this public key to the user:", fg=typer.colors.YELLOW)
    typer.echo(keypair.public_key)


@secret_app.command("add")
def add_secret(
    hostname: str = typer.Argument(..., help="Target hostname"),
    name: str = typer.Argument(..., help="Secret name"),
    file: Path = typer.Argument(..., help="File containing the secret"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Encrypt a file for a host, without placement metadata.

    The result lands in deploy/hosts/<host>/<name>.age but nothing records
    where it should be written on the host, so NixOS will not deploy it.
    Use 'aegis secret import' unless you are going to declare placement
    separately with 'aegis host set-placement'.
    \b
    Example:
        aegis secret add rama db-password ./password.txt
    """
    repo = get_secrets_repo(secrets_path)
    if not file.exists():
        typer.echo(f"Error: File not found: {file}", err=True)
        raise typer.Exit(1)

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Read secret
    content = file.read_text()

    # Encrypt
    admin_keys = admin_recipients(repo)
    
    output_path = repo.host_deploy_path(hostname) / f"{name}.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    crypto.encrypt_age(content, [host_age_key, *admin_keys], output_path)
    
    typer.secho(f"Added secret: {name} for {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Wrote: {output_path}")
    typer.secho(
        "\n  No manifest entry, so there is nothing for NixOS to reference "
        "and nothing deploys this.",
        fg=typer.colors.YELLOW,
    )
    typer.echo(
        f"  Give it a target: aegis secret import {name} --host {hostname} "
        f"--file {file} --target /run/<service>/<file>"
    )


# =============================================================================
# aegis role ...
# =============================================================================

@role_app.command("init")
def init_role(
    role: str = typer.Argument(..., help="Role name (e.g., kdc, dns)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Create a role keypair with no initial host members.

    The role private key is encrypted for the admin and stored in
    keys/roles/<role>.age.  Use 'aegis role add-host' to grant hosts
    access to this role.
    \b
    Examples:
        aegis role init kdc
        aegis role add-host kdc rama
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    existing = repo.get_role_config(role)
    if existing:
        typer.echo(f"Role {role} already exists")
        raise typer.Exit(1)

    typer.echo(f"Generating keypair for role {role}...")
    keypair = crypto.generate_age_keypair()

    admin_keys = admin_recipients(repo)

    # Store role private key encrypted for admin only
    role_key_path = repo.role_key_path(role)
    role_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, admin_keys, role_key_path)

    # Save public key
    role_pub_path = repo.role_pubkey_path(role)
    role_pub_path.parent.mkdir(parents=True, exist_ok=True)
    role_pub_path.write_text(keypair.public_key)

    # Save role config with empty hosts list
    role_config = config.RoleConfig(name=role, hosts=[])
    repo.set_role_config(role_config)

    typer.secho(f"Created role: {role}", fg=typer.colors.GREEN)
    typer.echo(f"  Public key: {keypair.public_key}")
    typer.echo(f"  Role key:   {role_key_path}")
    typer.echo(f"\nNext: aegis role add-host {role} <hostname>")


@role_app.command("add-host")
def add_host_to_role(
    role: str = typer.Argument(..., help="Role name"),
    hostname: str = typer.Argument(..., help="Hostname to add to the role"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Add a host to a role, giving it access to the role's secrets.

    Decrypts the admin-held role private key and re-encrypts it for the
    target host, writing the result to
    build/hosts/<hostname>/roles/<role>.age.

    The role's own secrets are not re-encrypted -- there is one copy of each,
    encrypted to the role -- so this is all it takes to move or extend a
    service: the host's manifest gains an entry for every secret the role
    holds, and the plaintext is never needed again.
    \b
    Example:
        aegis role add-host domain-sea.fudo.org rama
    """
    repo = get_secrets_repo(secrets_path)

    role_config = repo.get_role_config(role)
    if not role_config:
        typer.echo(f"Error: Role {role} not found. Use 'aegis role init {role}' first.", err=True)
        raise typer.Exit(1)

    if hostname in role_config.hosts:
        typer.echo(f"Host {hostname} is already a member of role {role}")
        raise typer.Exit(1)

    # Membership is a declaration and can precede the machine, but the key
    # must not: handing a role key to a host that is retired, or that Aegis
    # does not deliver to, is exactly the leak the status field exists to
    # prevent.  Record the membership; build-role-keys writes the key once
    # the host goes active.
    host_config = repo.get_host_config(hostname)
    if host_config and not host_config.deploys:
        role_config.hosts.append(hostname)
        repo.set_role_config(role_config)
        typer.secho(
            f"Added {hostname} to role {role} (no key written: status is "
            f"{host_config.status})",
            fg=typer.colors.YELLOW,
        )
        typer.echo(
            f"  It will get one from 'aegis build role-keys' once it is active.")
        return

    role_key_path = repo.role_key_path(role)
    if not role_key_path.exists():
        typer.echo(f"Error: Role key not found: {role_key_path}", err=True)
        typer.echo(f"Re-initialize the role with: aegis role init {role}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Adding {hostname} to role {role}...")

    try:
        role_privkey = crypto.decrypt_age(role_key_path)
    except Exception as e:
        typer.echo(f"Error decrypting role key: {e}", err=True)
        raise typer.Exit(1)

    host_age_key = get_host_age_pubkey(hostname, repo)
    admin_keys = admin_recipients(repo)

    out_path = repo.host_role_key_path(hostname, role)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(role_privkey, [host_age_key, *admin_keys], out_path)

    role_config.hosts.append(hostname)
    repo.set_role_config(role_config)

    for conflict in reconcile_host_roles(repo, hostname):
        typer.secho(f"  Warning: {conflict}", fg=typer.colors.YELLOW, err=True)

    typer.secho(f"Added {hostname} to role {role}", fg=typer.colors.GREEN)
    typer.echo(f"  Role key: {out_path}")
    typer.echo(f"  Members:  {', '.join(role_config.hosts)}")

    role_secrets = repo.list_role_secrets(role)
    if role_secrets:
        typer.echo(
            f"  Secrets:  {', '.join(role_secrets)} "
            f"(now in {hostname}'s manifest)")


@role_app.command("remove-host")
def remove_host_from_role(
    role: str = typer.Argument(..., help="Role name"),
    hostname: str = typer.Argument(..., help="Hostname to remove from the role"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Remove a host from a role and delete its per-host role key file.

    The role's secrets are dropped from the host's manifest too, so the next
    deploy stops writing them.  The host keeps whatever it already decrypted,
    so treat anything the role protected as disclosed to it: revoking access
    is not the same as rotating the secret.
    \b
    Example:
        aegis role remove-host kdc oldhost
    """
    repo = get_secrets_repo(secrets_path)

    role_config = repo.get_role_config(role)
    if not role_config:
        typer.echo(f"Error: Role {role} not found.", err=True)
        raise typer.Exit(1)

    if hostname not in role_config.hosts:
        typer.echo(f"Host {hostname} is not a member of role {role}")
        raise typer.Exit(1)

    key_file = repo.host_role_key_path(hostname, role)
    if key_file.exists():
        key_file.unlink()
        typer.echo(f"  Removed: {key_file}")

    role_config.hosts = [h for h in role_config.hosts if h != hostname]
    repo.set_role_config(role_config)

    dropped = repo.list_role_secrets(role)
    for conflict in reconcile_host_roles(repo, hostname):
        typer.secho(f"  Warning: {conflict}", fg=typer.colors.YELLOW, err=True)

    typer.secho(f"Removed {hostname} from role {role}", fg=typer.colors.GREEN)
    if dropped:
        typer.echo(
            f"  Dropped from its manifest: {', '.join(dropped)}")
        typer.secho(
            f"  {hostname} has already read these; rotate them if that "
            f"matters: aegis secret import <name> --role {role} --force",
            fg=typer.colors.YELLOW,
        )
    if role_config.hosts:
        typer.echo(f"  Remaining members: {', '.join(role_config.hosts)}")


@role_app.command("set-placement")
def set_role_placement(
    role: str = typer.Argument(..., help="Role name"),
    kind: str = typer.Argument(..., help="'secret:<name>', naming one of the role's secrets"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    target: Optional[str] = typer.Option(None, "--target", help="Destination path on every member host"),
    user: Optional[str] = typer.Option(None, "--user", help="Owner user"),
    group: Optional[str] = typer.Option(None, "--group", help="Owner group"),
    mode: Optional[str] = typer.Option(None, "--mode", help="File permissions, e.g. 0400"),
    clear: bool = typer.Option(False, "--clear", help="Remove overrides and fall back to defaults"),
):
    """Declare where a role's decrypted secret belongs on its member hosts.

    The counterpart of 'aegis host set-placement' for secrets that belong to a
    role rather than a machine.  It lives in src/roles/<role>.toml and applies
    to every member, present and future, so a host joining the role lands the
    secret in the same place without being told.
    \b
    Example:
        aegis role set-placement authentik secret:ldap-bind-password \\
            --target /run/authentik/ldap-password --user authentik
    """
    if not kind.startswith("secret:"):
        typer.echo(
            f"Error: unknown placement kind {kind!r}. Expected 'secret:<name>'.",
            err=True,
        )
        raise typer.Exit(1)

    repo = get_secrets_repo(secrets_path)

    role_config = repo.get_role_config(role)
    if role_config is None:
        typer.echo(f"Error: role {role} is not configured", err=True)
        typer.echo(f"Create it with: aegis role init {role}", err=True)
        raise typer.Exit(1)

    secret_name = kind.removeprefix("secret:")
    if secret_name not in repo.list_role_secrets(role):
        typer.secho(
            f"Note: role {role} holds no secret named {secret_name!r}; "
            f"recording the placement anyway, for when it does.",
            fg=typer.colors.YELLOW,
        )

    if clear:
        role_config.placement.pop(kind, None)
        repo.set_role_config(role_config)
        reconcile_role_members(repo, role)
        typer.secho(f"Cleared placement for {role}/{kind}", fg=typer.colors.GREEN)
        return

    placement = config.Placement(target=target, user=user, group=group, mode=mode)
    if placement.is_empty():
        current = role_config.placement_for(kind)
        typer.echo(f"{role}/{kind}: {current.to_dict() or '(defaults)'}")
        return

    record_role_placement(repo, role, kind, placement)
    members = reconcile_role_members(repo, role)

    updated = repo.get_role_config(role)
    assert updated is not None
    typer.secho(f"Set placement for {role}/{kind}", fg=typer.colors.GREEN)
    for key, value in sorted(updated.placement_for(kind).to_dict().items()):
        typer.echo(f"  {key}: {value}")
    if members:
        typer.echo(f"  Manifests refreshed: {', '.join(members)}")


# =============================================================================
# aegis nexus keygen
# =============================================================================

@nexus_app.command("keygen")
def nexus_keygen(
    output: Path = typer.Argument(..., help="Output file path for the key"),
    algorithm: str = typer.Option("HmacSHA512", "--algorithm", "-a", help="HMAC algorithm (e.g., HmacSHA256, HmacSHA512)"),
    seed: Optional[str] = typer.Option(None, "--seed", "-s", help="Seed for key generation (for reproducibility)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print verbose output"),
):
    """Generate a Nexus DDNS authentication key.
    
    Creates an HMAC key for authenticating Nexus DDNS clients to servers.
    The key is written in the format: ALGORITHM:BASE64_ENCODED_KEY
    \b
    Example:
        aegis nexus keygen server.key
        aegis nexus keygen client.key --algorithm HmacSHA256
    """
    from . import nexus
    
    typer.echo(f"Generating Nexus key with algorithm: {algorithm}")
    
    try:
        key_path = nexus.generate_key(
            output_path=output,
            algorithm=algorithm,
            seed=seed,
            verbose=verbose,
        )
        
        typer.secho(f"\nKey generated successfully!", fg=typer.colors.GREEN)
        typer.echo(f"  Location: {key_path}")
        
        # Show the algorithm
        algo, _ = nexus.read_key(key_path)
        typer.echo(f"  Algorithm: {algo}")
        
    except Exception as e:
        typer.echo(f"Error generating key: {e}", err=True)
        raise typer.Exit(1)


# =============================================================================
# aegis status / verify / secret list / host set-placement
# =============================================================================

@app.command("status", rich_help_panel=PANEL_DAILY)
def status(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Show what is configured, and what still needs building.

    Covers every host, user and role in the repo.  For drift between what
    src/ declares and what deploy/ actually holds, use 'aegis check'.
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)

    typer.echo("Aegis Secrets Status")
    typer.echo("=" * 40)

    def yn(v: bool) -> str:
        return "yes" if v else "no"

    hosts = repo.list_hosts()
    users = repo.list_users()
    roles = repo.list_roles()

    typer.echo(f"\nConfigured hosts: {len(hosts)}")
    for hostname in hosts:
        host_config = repo.get_host_config(hostname)
        build_path = repo.host_deploy_path(hostname)

        has_master_key = bool(host_config and host_config.age_pubkey)

        ssh_dir = build_path / "ssh"
        has_ssh = ssh_dir.is_dir() and any(ssh_dir.glob("*.age"))

        has_nexus = (build_path / "nexus-key.age").exists()
        has_keytab = (build_path / "keytab.age").exists()

        roles_dir = build_path / "roles"
        host_roles = sorted(f.stem for f in roles_dir.glob("*.age")) if roles_dir.is_dir() else []

        parts = [
            f"master-key={yn(has_master_key)}",
            f"ssh={yn(has_ssh)}",
            f"nexus={yn(has_nexus)}",
            f"keytab={yn(has_keytab)}",
        ]
        if host_roles:
            parts.append(f"roles=[{', '.join(host_roles)}]")

        typer.echo(f"  {hostname}: {', '.join(parts)}")

    typer.echo(f"\nConfigured users: {len(users)}")
    for username in users:
        user_config = repo.get_user_config(username)
        if user_config:
            typer.echo(f"  {username}: hosts=[{', '.join(user_config.hosts)}]")

    typer.echo(f"\nConfigured roles: {len(roles)}")
    for role in roles:
        role_config = repo.get_role_config(role)
        if role_config:
            has_master_key = repo.role_key_path(role).exists()
            has_pubkey = (repo.role_pubkey_path(role)).exists()
            members = ", ".join(role_config.hosts) if role_config.hosts else "(none)"
            line = (
                f"  {role}: hosts=[{members}],"
                f" master-key={yn(has_master_key)}, pubkey={yn(has_pubkey)}"
            )
            role_secrets = repo.list_role_secrets(role)
            if role_secrets:
                line += f", secrets=[{', '.join(role_secrets)}]"
            typer.echo(line)


@secret_app.command("list")
def list_secrets(
    hostname: Optional[str] = typer.Argument(None, help="Hostname (optional, list all if omitted)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """List secrets for a host or all hosts.

    Secrets encrypted to a role are stored once, under the role, so they are
    listed separately: a member host deploys them without holding a copy.
    \b
    Examples:
        aegis secret list
        aegis secret list rama
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)

    if hostname:
        hosts = [hostname]
    else:
        hosts = repo.list_hosts()

    for host in hosts:
        typer.echo(f"\n{host}:")
        deploy = repo.host_deploy_path(host)

        via_role, _ = host_secrets.role_secret_entries(repo, host)

        if not deploy.exists():
            typer.echo("  (no output)")
        else:
            # Recurse: most of a host's secrets live in ssh/, roles/, secrets/
            # and users/, so a top-level glob reports one file where there are
            # eleven.
            files = sorted(deploy.rglob("*.age"))
            if not files and not via_role:
                typer.echo("  (no secrets)")

            for secret_file in files:
                size = secret_file.stat().st_size
                rel = secret_file.relative_to(deploy)
                typer.echo(f"  {rel} ({size} bytes)")

        for name, entry in sorted(via_role.items()):
            path = repo.role_secret_path(entry.role or "", name)
            size = path.stat().st_size if path.exists() else 0
            typer.echo(f"  via role {entry.role}: {name} ({size} bytes)")


@app.command("verify", rich_help_panel=PANEL_DAILY)
def verify(
    hostname: str = typer.Argument(..., help="Hostname to verify"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Verify a host can decrypt its secrets.

    \b
    Example:
        aegis verify rama
    """
    repo = get_secrets_repo(secrets_path)
    
    # This would require having the host's private key, which we don't
    # In practice, verification happens at deployment time
    typer.echo(f"Verification for {hostname}:")
    typer.echo("  Note: Full verification requires the host's private key")
    typer.echo("  Checking that secrets exist and are properly formatted...")
    
    deploy = repo.host_deploy_path(hostname)
    if not deploy.exists():
        typer.echo("  No output found")
        raise typer.Exit(1)

    try:
        expected = len(admin_recipients(repo, validate=False)) + 1
    except AegisError:
        expected = None

    problems = 0
    for secret_file in sorted(deploy.rglob("*.age")):
        rel = secret_file.relative_to(deploy)
        header = secret_file.read_bytes()[:40]
        if not header.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"):
            typer.secho(f"  {rel}: WARNING (unexpected format)", fg=typer.colors.YELLOW)
            problems += 1
            continue

        count = crypto.recipients_of(secret_file)
        note = f"{count} recipients" if count else "valid age format"
        if expected and count and count < expected and rel.parts[0] != "users":
            typer.secho(
                f"  {rel}: WARNING ({count} recipients, expected >= {expected})",
                fg=typer.colors.YELLOW,
            )
            problems += 1
        else:
            typer.echo(f"  {rel}: OK ({note})")

    if problems:
        typer.echo("")
        typer.secho(f"{problems} file(s) need attention; see 'aegis check'",
                    fg=typer.colors.YELLOW)


@host_app.command("set-placement")
def set_placement(
    hostname: str = typer.Argument(..., help="Hostname"),
    kind: str = typer.Argument(..., help="'ssh-host-keys', 'keytab', 'nexus-key', or 'secret:<name>'"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    target: Optional[str] = typer.Option(None, "--target", help="Destination path on the host"),
    target_dir: Optional[str] = typer.Option(None, "--target-dir", help="Destination directory (SSH keys)"),
    user: Optional[str] = typer.Option(None, "--user", help="Owner user"),
    group: Optional[str] = typer.Option(None, "--group", help="Owner group"),
    mode: Optional[str] = typer.Option(None, "--mode", help="File permissions, e.g. 0400"),
    clear: bool = typer.Option(False, "--clear", help="Remove overrides and fall back to defaults"),
):
    """Declare where a host's decrypted secret belongs.

    Placement lives in src/hosts/<host>.toml, so the manifest in the deploy
    directory stays a derived artifact: it can be regenerated from scratch
    without losing target paths.  Previously these were flags on the build
    commands, which meant the only copy lived in generated output and changing
    one required regenerating the key.

    Run 'aegis reencrypt --host <host>' afterwards to refresh the manifest.
    \b
    Example:
        aegis host set-placement rama secret:db-password \\
            --target /run/postgresql/password --user postgres --mode 0400
    """
    repo = get_secrets_repo(secrets_path)

    known = set(config.PLACEMENT_KINDS)
    if kind not in known and not kind.startswith("secret:"):
        typer.echo(
            f"Error: unknown placement kind {kind!r}.\n"
            f"Expected one of {', '.join(sorted(known))}, or 'secret:<name>'.",
            err=True,
        )
        raise typer.Exit(1)

    host_config = repo.get_host_config(hostname)
    if host_config is None:
        typer.echo(f"Error: host {hostname} is not configured", err=True)
        typer.echo(f"Add it with: aegis host add {hostname}", err=True)
        raise typer.Exit(1)

    if clear:
        host_config.placement.pop(kind, None)
        repo.set_host_config(host_config)
        typer.secho(f"Cleared placement for {hostname}/{kind}", fg=typer.colors.GREEN)
        return

    placement = config.Placement(
        target=target, target_dir=target_dir, user=user, group=group, mode=mode)
    if placement.is_empty():
        current = host_config.placement_for(kind)
        typer.echo(f"{hostname}/{kind}: {current.to_dict() or '(defaults)'}")
        return

    record_placement(repo, hostname, kind, placement)

    updated = repo.get_host_config(hostname)
    assert updated is not None
    typer.secho(f"Set placement for {hostname}/{kind}", fg=typer.colors.GREEN)
    for key, value in sorted(updated.placement_for(kind).to_dict().items()):
        typer.echo(f"  {key}: {value}")
    typer.echo("")
    typer.echo(f"Apply it: aegis reencrypt --host {hostname}")



# =============================================================================
# Listing and deletion
#
# Every category answers the same three questions -- what exists, what is in
# it, and how to get rid of it. `admin` had all three; the rest had create and
# little else, so a role could be made and never listed or removed.
#
# The delete commands share one renderer and one rule: name what still points
# at the thing and stop, rather than cascading. See aegis/removal.py.
# =============================================================================

SecretsPathOpt = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)")
ForceOpt = typer.Option(False, "--force", "-f", help="Delete even though something still refers to it")
YesOpt = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt")
DryRunOpt = typer.Option(False, "--dry-run", "-n", help="Show what would be removed and stop")


@host_app.command("list")
def list_hosts_cmd(
    status: Optional[str] = typer.Option(None, "--status", help="Only hosts with this status (active, pending, retired, external)"),
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List declared hosts, their status, and what is deployed to each.

    A host with output but no master key cannot decrypt any of it; a host with
    a key and no output has nothing to decrypt yet. Both are worth seeing at a
    glance.
    \b
    Examples:
        aegis host list
        aegis host list --status retired
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    hosts = repo.list_hosts()
    if not hosts:
        typer.echo("No hosts declared. Add one with: aegis host add <hostname>")
        return

    for hostname in hosts:
        host_config = repo.get_host_config(hostname)
        host_status = host_config.status if host_config else config.STATUS_ACTIVE
        if status and host_status != status:
            continue

        deploy = repo.host_deploy_path(hostname)
        files = len(list(deploy.rglob("*.age"))) if deploy.is_dir() else 0
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        key = "key" if (host_config and host_config.age_pubkey) else "NO KEY"

        typer.echo(
            f"{hostname:24} {host_status:9} {key:7} "
            f"{files:3} file(s)  roles: {', '.join(manifest.roles) or '-'}"
        )


@host_app.command("delete")
def delete_host_cmd(
    hostname: str = typer.Argument(..., help="Host to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a host, its declaration and everything deployed to it.

    Usually the wrong verb. A machine that is gone should be retired --
    'aegis host set-status <host> retired' -- which keeps the record of what
    it held so you know what to rotate. Deleting removes that record too, so
    it refuses while the host is active with secrets on it.
    \b
    Example:
        aegis host delete old-box --dry-run
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_host_removal(repo, hostname),
        force=force, yes=yes, dry_run=dry_run,
    )


@role_app.command("list")
def list_roles_cmd(
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List roles, their members and the secrets they carry.

    A role with members but no key file cannot decrypt anything; 'aegis build
    role-keys' is what fills that in.
    \b
    Example:
        aegis role list
    """
    repo = get_secrets_repo(secrets_path)
    roles = repo.list_roles()
    if not roles:
        typer.echo("No roles declared. Create one with: aegis role init <name>")
        return

    for role in roles:
        role_config = repo.get_role_config(role)
        members = role_config.hosts if role_config else []
        secrets = repo.list_role_secrets(role)
        key = "key" if repo.role_key_path(role).exists() else "NO KEY"

        typer.echo(f"{role:32} {key:7} {len(members):2} host(s)  {len(secrets):2} secret(s)")
        if members:
            typer.echo(f"    hosts:   {', '.join(sorted(members))}")
        if secrets:
            typer.echo(f"    secrets: {', '.join(secrets)}")


@role_app.command("delete")
def delete_role_cmd(
    role: str = typer.Argument(..., help="Role to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a role: its key, its shared secrets and every member's copy.

    Refuses while any host manifest still declares one of its secrets -- the
    aegis NixOS module fails evaluation on a role secret the host cannot
    decrypt, so that reference would break the member's build, not just its
    service.
    \b
    Example:
        aegis role delete legacy-app --dry-run
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_role_removal(repo, role),
        force=force, yes=yes, dry_run=dry_run,
    )


@user_app.command("list")
def list_users_cmd(
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List users and the hosts their secrets are deployed to.
    \b
    Example:
        aegis user list
    """
    repo = get_secrets_repo(secrets_path)
    users = repo.list_users()
    if not users:
        typer.echo("No users declared. Add one with: aegis user add <username>")
        return

    for username in users:
        user_config = repo.get_user_config(username)
        hosts = sorted(repo.resolve_user_allowed_hosts(user_config)) if user_config else []
        key = "key" if repo.user_key_path(username).exists() else "NO KEY"
        typer.echo(f"{username:24} {key:7} {len(hosts):2} host(s)  {', '.join(hosts) or '-'}")


@user_app.command("delete")
def delete_user_cmd(
    username: str = typer.Argument(..., help="User to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a user, their deployment key and every host's copy of it.
    \b
    Example:
        aegis user delete former-contractor
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_user_removal(repo, username),
        force=force, yes=yes, dry_run=dry_run,
    )


@secret_app.command("delete")
def delete_secret_cmd(
    name: str = typer.Argument(..., help="Secret to delete"),
    host: List[str] = typer.Option([], "--host", "-H", help="Only from this host (repeatable)"),
    role: List[str] = typer.Option([], "--role", "-R", help="Only from this role (repeatable)"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a secret's ciphertext and its manifest entries.

    With no --host or --role, every recipient that actually carries it --
    deleting it from one host and silently leaving it on three others is the
    thing worth avoiding.
    \b
    Examples:
        aegis secret delete stale-token --dry-run
        aegis secret delete stale-token --host rama
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_secret_removal(repo, name, list(host), list(role)),
        force=force, yes=yes, dry_run=dry_run,
    )


@ssh_app.command("list")
def list_ssh_cmd(
    hostname: Optional[str] = typer.Argument(None, help="Host (optional; all hosts if omitted)"),
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List the SSH host keys declared for a host.

    Only entries carrying a type become services.openssh.hostKeys; keys shown
    under [secrets] are delivered but not offered to sshd.
    \b
    Examples:
        aegis ssh list
        aegis ssh list nomenclator-0
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    hosts = [hostname] if hostname else repo.list_hosts()

    for host in hosts:
        manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
        auxiliary = sorted(
            name for name, entry in manifest.secrets.items()
            if entry.source.startswith("ssh/")
        )
        if not manifest.ssh_host_keys and not auxiliary:
            continue

        typer.echo(f"\n{host}:")
        for entry in manifest.ssh_host_keys:
            typer.echo(f"  sshd      {entry.target:24} type {entry.type or '(none)'}")
        for name in auxiliary:
            typer.echo(f"  [secrets] {name}")


@ssh_app.command("delete")
def delete_ssh_cmd(
    hostname: str = typer.Argument(..., help="Host whose SSH keys to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a host's SSH keys and their manifest entries.

    This is the host's identity: known_hosts and SSHFP records stop matching.
    To re-encrypt for a changed recipient set instead, use 'aegis reencrypt'.
    \b
    Example:
        aegis ssh delete decommissioned-box
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_ssh_removal(repo, hostname),
        force=force, yes=yes, dry_run=dry_run,
    )


@nexus_app.command("list")
def list_nexus_cmd(
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List hosts holding a Nexus HMAC key.
    \b
    Example:
        aegis nexus list
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    found = False
    for host in repo.list_hosts():
        manifest = host_secrets.load_host_manifest(repo.deploy_path, host)
        if manifest.nexus_key is None:
            continue
        found = True
        present = (repo.host_deploy_path(host) / "nexus-key.age").exists()
        typer.echo(
            f"{host:24} {manifest.nexus_key.target}"
            f"{'' if present else '   (declared, no key file)'}"
        )

    if not found:
        typer.echo("No host declares a nexus key. Add one with: aegis nexus keygen")


@nexus_app.command("delete")
def delete_nexus_cmd(
    hostname: str = typer.Argument(..., help="Host whose Nexus key to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a host's Nexus HMAC key and its manifest entry.
    \b
    Example:
        aegis nexus delete old-client
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_nexus_removal(repo, hostname),
        force=force, yes=yes, dry_run=dry_run,
    )


@dnssec_app.command("list")
def list_dnssec_cmd(
    secrets_path: Optional[Path] = SecretsPathOpt,
):
    """List domains with a DNSSEC key signing key.
    \b
    Example:
        aegis dnssec list
    """
    repo = get_secrets_repo(secrets_path)
    domains = repo.list_dnssec_domains()
    if not domains:
        typer.echo("No DNSSEC keys. Create one with: aegis dnssec generate <domain>")
        return

    for domain in domains:
        deploy = repo.dnssec_deploy_path(domain)
        files = len(list(deploy.glob("*.age"))) if deploy.is_dir() else 0
        role = repo.get_role_config(f"dns-master-{domain}")
        holders = ", ".join(role.hosts) if role and role.hosts else "-"
        typer.echo(f"{domain:32} {files:2} key file(s)  held by: {holders}")


@dnssec_app.command("delete")
def delete_dnssec_cmd(
    domain: str = typer.Argument(..., help="Domain whose KSK to delete"),
    secrets_path: Optional[Path] = SecretsPathOpt,
    force: bool = ForceOpt,
    yes: bool = YesOpt,
    dry_run: bool = DryRunOpt,
):
    """Delete a domain's DNSSEC key signing key.

    Refuses while the dns-master-<domain> role still has members: they are the
    hosts signing with it.
    \b
    Example:
        aegis dnssec delete test.fudo.org --dry-run
    """
    repo = get_secrets_repo(secrets_path)
    run_removal(
        removal.plan_dnssec_removal(repo, domain),
        force=force, yes=yes, dry_run=dry_run,
    )


def main():
    """Entry point.

    Library code raises AegisError; this is the single place that turns it
    into a process exit, so per-item loops can catch and skip instead.
    """
    try:
        app()
    except AegisError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED, err=True)
        sys.exit(1)


# Registered at import time so that `from aegis.cli import app` (tests, and
# any embedding) sees the full command surface, not just the top-level ones.
_register_subcommands()


if __name__ == "__main__":
    main()
