"""``aegis keytab`` -- named Kerberos keytabs.

Every realm member already gets a host keytab: its own ``<service>/<fqdn>``
principals, at one path, owned by root.  That covers a machine proving it is
itself, and nothing else.

A *named* keytab is the explicit form.  It holds whatever principals are
declared for it and goes wherever it is declared to go, which is what makes
the other cases expressible:

  * a client identity -- an agent that needs to *authenticate as* something,
    rather than accept connections as a host;
  * a service principal that moves between machines with its service, by
    being delivered to a role rather than a host;
  * a keytab for something Aegis does not deploy to at all -- a container
    scheduled by Kubernetes, an appliance, a machine someone else runs.  That
    last one is the export-only mode: the keytab is still built, rebuilt on
    rekey, and accounted for by ``check``; it just leaves through
    ``aegis keytab export`` instead of a manifest.
"""

import os
import stat
from pathlib import Path
from typing import List, Optional

import typer

from . import config, crypto, realm as realm_mod
from .errors import AegisError, RealmError

keytab_app = typer.Typer(
    name="keytab",
    help="Build Kerberos keytabs holding an arbitrary set of principals.",
    no_args_is_help=True,
)


def _repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    from .cli import get_secrets_repo
    return get_secrets_repo(secrets_path)


def _save(repo: config.SecretsRepo, ref: realm_mod.KeytabRef) -> None:
    """Write a modified spec back to its realm."""
    realm_config = realm_mod.load(repo, ref.realm)
    realm_config.keytabs[ref.name] = ref.spec
    realm_mod.save(repo, realm_config)


def _rebuild_hint(ref: realm_mod.KeytabRef) -> str:
    return f"aegis build keytabs --force --realm {ref.realm}"


def _describe_delivery(spec: realm_mod.KeytabSpec) -> str:
    parts = [f"host {h}" for h in sorted(spec.hosts)]
    parts += [f"role {r}" for r in sorted(spec.roles)]
    return ", ".join(parts) if parts else "export only (not deployed)"


def _drop_from_manifests(
    repo: config.SecretsRepo, name: str, hostnames: List[str]
) -> List[str]:
    """Remove a keytab entry from the named hosts' manifests.

    Done here rather than left to the next build: between the two, the host
    would carry a manifest naming a file that has just been deleted, and that
    fails its boot rather than its build.
    """
    from . import host_secrets

    touched = []
    for hostname in hostnames:
        manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
        if manifest.keytabs.pop(name, None) is not None:
            host_secrets.save_host_manifest(repo.deploy_path, manifest)
            touched.append(hostname)
    return touched


# =============================================================================
# Declaring
# =============================================================================

@keytab_app.command("new")
def keytab_new(
    name: str = typer.Argument(..., help="Keytab name, e.g. 'hermes'"),
    realm: str = typer.Option(..., "--realm", "-r", help="Realm whose principals it holds"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    principal: List[str] = typer.Option([], "--principal", "-p", help="Principal to include (repeatable)"),
    host: List[str] = typer.Option([], "--host", "-H", help="Host that receives its own copy (repeatable)"),
    role: List[str] = typer.Option([], "--role", "-R", help="Role that receives one shared copy (repeatable)"),
    create_missing: bool = typer.Option(False, "--create-missing", help="Create any principal that does not exist yet"),
    note: str = typer.Option("", "--note", help="What this keytab is for"),
):
    """Declare a named keytab.

    With neither --host nor --role the keytab is export-only: built and stored
    encrypted to the admin set, and collected with 'aegis keytab export'.
    That is the mode for a consumer Aegis does not deploy to, such as a
    workload scheduled by Kubernetes -- Aegis still owns the principal, so the
    keytab is rebuilt on rekey and reported by 'aegis check'.
    \b
    Examples:
        aegis keytab new hermes --realm SEA.FUDO.ORG \\
            --principal hermes/hermes.sea.fudo.org --create-missing \\
            --note "Hermes agent, deployed to k8s as a secret"

        aegis keytab new nextcloud --realm SEA.FUDO.ORG \\
            --principal HTTP/cloud.sea.fudo.org --role nextcloud
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)

    if name in realm_config.keytabs:
        typer.echo(f"Error: keytab {name!r} already exists in {realm}", err=True)
        typer.echo(f"Inspect it with: aegis keytab show {name}", err=True)
        raise typer.Exit(1)

    # Names are the manifest's keys and the export filename, so they have to
    # be unique repo-wide rather than per-realm.
    existing = [ref for ref in realm_mod.all_keytabs(repo) if ref.name == name]
    if existing:
        typer.echo(
            f"Error: keytab {name!r} is already declared by realm "
            f"{existing[0].realm}. Keytab names must be unique across realms.",
            err=True)
        raise typer.Exit(1)

    _validate_recipients(repo, host, role)

    principals = list(dict.fromkeys(principal))
    if principals:
        _resolve_principals(repo, realm, principals, create_missing)

    realm_config = realm_mod.load(repo, realm)  # reload: creation rewrote it
    realm_config.keytabs[name] = realm_mod.KeytabSpec(
        principals=principals, hosts=list(host), roles=list(role), note=note)
    realm_mod.save(repo, realm_config)

    spec = realm_config.keytabs[name]
    typer.secho(f"Declared keytab: {name}", fg=typer.colors.GREEN)
    typer.echo(f"  Realm:      {realm}")
    typer.echo(f"  Principals: {', '.join(sorted(principals)) or '(none yet)'}")
    typer.echo(f"  Delivery:   {_describe_delivery(spec)}")
    typer.echo("")
    typer.echo(f"Build it: aegis build keytabs --realm {realm}")
    if spec.export_only:
        typer.echo(f"Then:     aegis keytab export {name} --output {name}.keytab")


def _validate_recipients(
    repo: config.SecretsRepo, hosts: List[str], roles: List[str]
) -> None:
    """Fail on a host or role that does not exist.

    Checked up front because the alternative is a keytab that declares a
    recipient every build then warns about, which is the kind of warning that
    stops being read.
    """
    unknown_hosts = [h for h in hosts if repo.get_host_config(h) is None]
    if unknown_hosts:
        typer.echo(
            f"Error: unknown host(s): {', '.join(unknown_hosts)}.\n"
            f"Add one with: aegis host add <hostname>", err=True)
        raise typer.Exit(1)

    known_roles = set(repo.list_roles())
    unknown_roles = [r for r in roles if r not in known_roles]
    if unknown_roles:
        typer.echo(
            f"Error: unknown role(s): {', '.join(unknown_roles)}.\n"
            f"Create one with: aegis role init <role>", err=True)
        raise typer.Exit(1)


def _resolve_principals(
    repo: config.SecretsRepo,
    realm: str,
    principals: List[str],
    create_missing: bool,
) -> None:
    """Ensure every principal exists in the realm, creating them if asked."""
    from .cli_realm import _InstantiatedRealm, _admin_keys

    stored = set(realm_mod.stored_principals(repo, realm))
    missing = [p for p in principals if p not in stored]
    if not missing:
        return

    if not create_missing:
        typer.echo(
            f"Error: principal(s) not in realm {realm}: {', '.join(missing)}.\n"
            f"Create them with --create-missing, or beforehand with:\n"
            + "\n".join(f"  aegis realm add-principal {realm} {p}" for p in missing),
            err=True)
        raise typer.Exit(1)

    admin_keys = _admin_keys(repo)
    from . import kerberos as krb

    typer.echo(f"Creating {len(missing)} principal(s) in {realm}...")
    with _InstantiatedRealm(repo, realm) as inst:
        for principal in missing:
            typer.echo(f"  {principal}")
            krb.add_principal(
                principal, inst.kdc_conf, inst.principals_dir, verbose=False)
            inst.store_principal(principal, admin_keys)

    fresh = realm_mod.load(repo, realm)
    for principal in missing:
        fresh.principals[principal] = realm_mod.classify(principal, realm)
    realm_mod.save(repo, fresh)


# =============================================================================
# Editing
# =============================================================================

@keytab_app.command("add-principal")
def keytab_add_principal(
    name: str = typer.Argument(..., help="Keytab name"),
    principal: str = typer.Argument(..., help="Principal to add"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    create: bool = typer.Option(False, "--create", help="Create the principal if it does not exist"),
):
    """Add a principal to a named keytab."""
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    if principal in ref.spec.principals:
        typer.echo(f"{name} already includes {principal}")
        return

    _resolve_principals(repo, ref.realm, [principal], create)

    ref.spec.principals.append(principal)
    _save(repo, ref)

    typer.secho(f"Added {principal} to keytab {name}", fg=typer.colors.GREEN)
    typer.echo(f"  Run: {_rebuild_hint(ref)}")


@keytab_app.command("remove-principal")
def keytab_remove_principal(
    name: str = typer.Argument(..., help="Keytab name"),
    principal: str = typer.Argument(..., help="Principal to remove"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Remove a principal from a named keytab.

    The principal itself is untouched -- it stays in the realm, and anything
    else holding it keeps working.  Note that the key is not rotated, so a
    consumer that already has the old keytab can still use it: rekey the
    principal if the point is to revoke access.
    """
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    if principal not in ref.spec.principals:
        typer.echo(f"Error: {name} does not include {principal}", err=True)
        raise typer.Exit(1)

    ref.spec.principals.remove(principal)
    _save(repo, ref)

    typer.secho(f"Removed {principal} from keytab {name}", fg=typer.colors.GREEN)
    typer.echo(f"  Run: {_rebuild_hint(ref)}")
    typer.secho(
        f"  Note: whoever already holds {name} can still use the old copy. "
        f"To revoke, rotate the key:\n"
        f"    aegis realm rekey-principal {ref.realm} {principal}",
        fg=typer.colors.YELLOW)


@keytab_app.command("add-host")
def keytab_add_host(
    name: str = typer.Argument(..., help="Keytab name"),
    hostname: str = typer.Argument(..., help="Host that should receive a copy"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Deliver a named keytab to a host, encrypted to its master key."""
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)
    _validate_recipients(repo, [hostname], [])

    if hostname in ref.spec.hosts:
        typer.echo(f"{name} already goes to host {hostname}")
        return

    ref.spec.hosts.append(hostname)
    _save(repo, ref)

    typer.secho(f"Keytab {name} will be delivered to {hostname}",
                fg=typer.colors.GREEN)
    typer.echo(f"  Run: {_rebuild_hint(ref)}")


@keytab_app.command("remove-host")
def keytab_remove_host(
    name: str = typer.Argument(..., help="Keytab name"),
    hostname: str = typer.Argument(..., help="Host to stop delivering to"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Stop delivering a named keytab to a host, and drop its copy."""
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    if hostname not in ref.spec.hosts:
        typer.echo(f"Error: {name} does not go to host {hostname}", err=True)
        raise typer.Exit(1)

    ref.spec.hosts.remove(hostname)
    _save(repo, ref)

    repo.host_keytab_path(hostname, name).unlink(missing_ok=True)
    _drop_from_manifests(repo, name, [hostname])

    typer.secho(f"Keytab {name} no longer goes to {hostname}",
                fg=typer.colors.GREEN)
    typer.echo(f"  Run: {_rebuild_hint(ref)}")
    typer.secho(
        f"  Note: {hostname} may still hold a decrypted copy. To revoke, "
        f"rotate the principals:\n"
        + "\n".join(f"    aegis realm rekey-principal {ref.realm} {p}"
                    for p in sorted(ref.spec.principals)),
        fg=typer.colors.YELLOW)


@keytab_app.command("add-role")
def keytab_add_role(
    name: str = typer.Argument(..., help="Keytab name"),
    role: str = typer.Argument(..., help="Role that should receive one shared copy"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Deliver a named keytab through a role.

    One ciphertext, decrypted in phase 2 by every member, so the keytab
    follows the service between machines on a membership change alone.
    """
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)
    _validate_recipients(repo, [], [role])

    if role in ref.spec.roles:
        typer.echo(f"{name} already goes to role {role}")
        return

    ref.spec.roles.append(role)
    _save(repo, ref)

    typer.secho(f"Keytab {name} will be delivered to role {role}",
                fg=typer.colors.GREEN)
    typer.echo(f"  Run: {_rebuild_hint(ref)}")


@keytab_app.command("remove-role")
def keytab_remove_role(
    name: str = typer.Argument(..., help="Keytab name"),
    role: str = typer.Argument(..., help="Role to stop delivering to"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Stop delivering a named keytab through a role, and drop its copy."""
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    if role not in ref.spec.roles:
        typer.echo(f"Error: {name} does not go to role {role}", err=True)
        raise typer.Exit(1)

    ref.spec.roles.remove(role)
    _save(repo, ref)

    repo.role_keytab_path(role, name).unlink(missing_ok=True)
    role_config = repo.get_role_config(role)
    dropped = _drop_from_manifests(
        repo, name, list(role_config.hosts) if role_config else [])

    typer.secho(f"Keytab {name} no longer goes to role {role}",
                fg=typer.colors.GREEN)
    if dropped:
        typer.echo(f"  Dropped from {len(dropped)} member manifest(s)")
    typer.echo(f"  Run: {_rebuild_hint(ref)}")


# =============================================================================
# Reading
# =============================================================================

@keytab_app.command("list")
def keytab_list(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    realm: Optional[str] = typer.Option(None, "--realm", "-r", help="Only this realm"),
):
    """List named keytabs."""
    repo = _repo(secrets_path)
    refs = realm_mod.all_keytabs(repo)
    if realm:
        refs = [ref for ref in refs if ref.realm == realm]

    if not refs:
        typer.echo("No named keytabs declared.")
        typer.echo("Create one with: aegis keytab new <name> --realm <REALM>")
        return

    for ref in refs:
        built = "built" if _built_copies(repo, ref) else "NOT BUILT"
        typer.echo(
            f"{ref.name}  [{ref.realm}]  "
            f"{len(ref.spec.principals)} principal(s)  "
            f"-> {_describe_delivery(ref.spec)}  ({built})")


def _built_copies(repo: config.SecretsRepo, ref: realm_mod.KeytabRef) -> list[Path]:
    """Ciphertexts that exist on disk for a keytab."""
    paths = [repo.host_keytab_path(h, ref.name) for h in ref.spec.hosts]
    paths += [repo.role_keytab_path(r, ref.name) for r in ref.spec.roles]
    if ref.spec.export_only:
        paths.append(repo.export_keytab_path(ref.name))
    return [p for p in paths if p.exists()]


@keytab_app.command("show")
def keytab_show(
    name: str = typer.Argument(..., help="Keytab name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
):
    """Show a named keytab's principals, recipients, and built copies."""
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)
    spec = ref.spec

    typer.echo(f"Keytab: {name}")
    typer.echo(f"  Realm:      {ref.realm}")
    if spec.note:
        typer.echo(f"  Note:       {spec.note}")
    typer.echo(f"  Delivery:   {_describe_delivery(spec)}")

    typer.echo("  Principals:")
    stored = set(realm_mod.stored_principals(repo, ref.realm))
    rotating = set(realm_mod.previous_principals(repo, ref.realm))
    for principal in sorted(spec.principals):
        marks = []
        if principal not in stored:
            marks.append("MISSING from realm")
        if principal in rotating:
            marks.append("rekey in progress")
        suffix = f"  ({'; '.join(marks)})" if marks else ""
        typer.echo(f"    {principal}{suffix}")
    if not spec.principals:
        typer.echo("    (none)")

    built = _built_copies(repo, ref)
    typer.echo("  Built copies:")
    for path in built:
        typer.echo(f"    {path}")
    if not built:
        typer.echo(f"    (none) -- run: {_rebuild_hint(ref)}")


# =============================================================================
# Exporting
# =============================================================================

@keytab_app.command("export")
def keytab_export(
    name: str = typer.Argument(..., help="Keytab name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write the decrypted keytab here (default: ./<name>.keytab)"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite an existing output file"),
):
    """Decrypt a named keytab to a file, for a consumer Aegis does not deploy to.

    This writes key material to disk in the clear, mode 0600.  It is the
    handoff point for anything outside Aegis's reach -- a Kubernetes secret,
    an appliance, a machine someone else runs -- so treat the output as
    something to move and delete, not to keep.
    \b
    Example:
        aegis keytab export hermes --output /tmp/hermes.keytab
        kubectl create secret generic hermes-keytab \\
            --from-file=krb5.keytab=/tmp/hermes.keytab
        shred -u /tmp/hermes.keytab

    Re-export after 'aegis realm rekey-principal': the old key keeps working
    only until the retained copy is pruned, and nothing outside Aegis is
    updated for you.  'aegis check' reports keytabs whose principals are
    mid-rotation.
    """
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    source = _export_source(repo, ref)
    destination = output or Path(f"{name}.keytab")

    if destination.exists() and not force:
        typer.echo(
            f"Error: {destination} exists. Pass --force to overwrite.", err=True)
        raise typer.Exit(1)

    content = crypto.decrypt_age_bytes(source)

    # Create it private, then write: a keytab that is briefly world-readable
    # is a keytab that was disclosed.
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    os.chmod(destination, 0o600)

    typer.secho(f"Exported {name} -> {destination}", fg=typer.colors.GREEN)
    typer.echo(f"  Realm:      {ref.realm}")
    typer.echo(f"  Principals: {', '.join(sorted(ref.spec.principals))}")
    typer.echo(f"  Mode:       0600")
    typer.echo("")
    typer.secho(
        "  This is plaintext key material. Move it to its destination and "
        "delete it.", fg=typer.colors.YELLOW)

    rotating = (
        set(ref.spec.principals)
        & set(realm_mod.previous_principals(repo, ref.realm)))
    if rotating:
        typer.secho(
            f"  Rekey in progress for {', '.join(sorted(rotating))}: this "
            f"keytab holds both keys. Prune the old one only once every "
            f"consumer has this copy.", fg=typer.colors.YELLOW)


def _export_source(
    repo: config.SecretsRepo, ref: realm_mod.KeytabRef
) -> Path:
    """The ciphertext to export, whichever delivery mode the keytab uses.

    Export-only keytabs have a copy of their own.  A deployed keytab can be
    exported too -- the admin set is a recipient of every copy, so any of them
    decrypts -- which matters when a keytab serves both a NixOS host and
    something outside Aegis.
    """
    candidates = [repo.export_keytab_path(ref.name)]
    candidates += [repo.host_keytab_path(h, ref.name) for h in sorted(ref.spec.hosts)]
    candidates += [repo.role_keytab_path(r, ref.name) for r in sorted(ref.spec.roles)]

    for path in candidates:
        if path.exists():
            return path

    raise RealmError(
        f"Keytab {ref.name} has not been built yet. "
        f"Run: {_rebuild_hint(ref)}"
    )


# =============================================================================
# Deleting
# =============================================================================

@keytab_app.command("delete")
def keytab_delete(
    name: str = typer.Argument(..., help="Keytab name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to the aegis-secrets repo (default: $AEGIS_SYSTEM)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt"),
):
    """Delete a named keytab declaration and every built copy.

    The principals stay in the realm: other keytabs may hold them, and a
    principal is not this keytab's to remove.  Whoever already holds a
    decrypted copy keeps working until the principals are rekeyed.
    """
    repo = _repo(secrets_path)
    ref = realm_mod.find_keytab(repo, name)

    built = _built_copies(repo, ref)
    if not yes:
        typer.echo(f"About to delete keytab {name} ({ref.realm}):")
        for path in built:
            typer.echo(f"  {path}")
        typer.echo(f"  the declaration in {repo.realm_config_path(ref.realm)}")
        if not typer.confirm("Proceed?"):
            raise typer.Exit(1)

    for path in built:
        path.unlink(missing_ok=True)

    realm_config = realm_mod.load(repo, ref.realm)
    realm_config.keytabs.pop(name, None)
    realm_mod.save(repo, realm_config)

    for hostname in _drop_from_manifests(repo, name, repo.list_deploying_hosts()):
        typer.echo(f"  Dropped from {hostname}'s manifest")

    typer.secho(f"Deleted keytab: {name}", fg=typer.colors.GREEN)
    if ref.spec.principals:
        typer.secho(
            f"  Principals remain in {ref.realm}. To revoke access held by "
            f"copies already distributed:\n"
            + "\n".join(f"    aegis realm rekey-principal {ref.realm} {p}"
                        for p in sorted(ref.spec.principals)),
            fg=typer.colors.YELLOW)
