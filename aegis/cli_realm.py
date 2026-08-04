"""``aegis realm`` — Kerberos realm management."""

import tempfile
from pathlib import Path
from typing import Optional

import typer

from . import config, crypto, realm as realm_mod
from . import kerberos as krb
from .errors import AegisError, RealmError

realm_app = typer.Typer(
    name="realm",
    help="Manage Kerberos realms, principals and cross-realm trust.",
    no_args_is_help=True,
)


def _repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    from .cli import get_secrets_repo
    return get_secrets_repo(secrets_path)


def _admin_keys(repo: config.SecretsRepo) -> list[str]:
    from .cli import admin_recipients
    return admin_recipients(repo)


class _InstantiatedRealm:
    """A realm database reconstructed in a temp directory.

    Everything about a realm lives encrypted in the repo; to do anything with
    it (add a principal, extract a keytab) it has to be decrypted into a
    throwaway KDC database first.  This context manager owns that lifecycle.
    """

    def __init__(self, repo: config.SecretsRepo, realm: str):
        self.repo = repo
        self.realm = realm
        self.config = realm_mod.load(repo, realm)
        self._tmp: Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self) -> "_InstantiatedRealm":
        key_path = self.repo.realm_key_path(self.realm)
        if not key_path.exists():
            raise RealmError(f"Realm key not found: {key_path}")

        self._tmp = tempfile.TemporaryDirectory(prefix="aegis-realm-")
        self.tmpdir = Path(self._tmp.name)
        self.realm_dir = self.tmpdir / self.realm
        self.realm_dir.mkdir()
        self.principals_dir = self.realm_dir / "principals"
        self.principals_dir.mkdir()

        self.key_file = self.realm_dir / "realm.key"
        self.key_file.write_bytes(crypto.decrypt_age_bytes(key_path))

        stored = self.repo.realm_principals_path(self.realm)
        if stored.is_dir():
            for princ_file in sorted(stored.glob("*.age")):
                target = self.principals_dir / f"{princ_file.stem}.key"
                target.write_bytes(crypto.decrypt_age_bytes(princ_file))

        self.kdc_conf = krb.instantiate_realm(
            self.realm, self.realm_dir, etypes=self.config.etypes
        )
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()

    def store_principal(self, principal: str, admin_keys: list[str]) -> Path:
        """Encrypt a principal's key file back into the repo."""
        stem = realm_mod.principal_filename(principal)
        src = self.principals_dir / f"{stem}.key"
        if not src.exists():
            raise RealmError(f"Principal file not produced: {src}")

        out = self.repo.realm_principals_path(self.realm) / f"{stem}.age"
        out.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(src.read_bytes(), admin_keys, out)
        return out


# =============================================================================
# Realm lifecycle
# =============================================================================

@realm_app.command("init")
def realm_init(
    realm: str = typer.Argument(..., help="Realm name (e.g., FUDO.ORG)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="DNS domain this realm serves"),
    kdc_role: str = typer.Option("kdc", "--kdc-role", help="Role whose members run the KDC"),
    etypes: Optional[str] = typer.Option(None, "--etypes", help="Comma-separated encryption types"),
):
    """Initialize a new Kerberos realm.

    Creates the realm master key and initial database, then stores both --
    plus a realm.toml recording the etypes and lifetimes actually used -- in
    src/kerberos/realms/<REALM>/.
    """
    repo = _repo(secrets_path)
    repo.ensure_structure()

    realm_dir = repo.realm_path(realm)
    if realm_dir.exists():
        typer.echo(f"Realm {realm} already exists at {realm_dir}")
        raise typer.Exit(1)

    admin_keys = _admin_keys(repo)

    etype_list = (
        [e.strip() for e in etypes.split(",")] if etypes
        else list(realm_mod.DEFAULT_ETYPES)
    )

    typer.echo(f"Initializing Kerberos realm: {realm}")

    with tempfile.TemporaryDirectory(prefix="aegis-realm-init-") as tmp:
        tmpdir = Path(tmp)

        typer.echo("  Generating realm master key and initial database...")
        created = krb.initialize_realm(realm, tmpdir, etypes=etype_list, verbose=True)

        realm_dir.mkdir(parents=True, exist_ok=True)
        principals_dir = realm_dir / "principals"
        principals_dir.mkdir(exist_ok=True)

        # The realm master key is binary (kstash output).  Reading it as text
        # mangles it, and produced realms that build-keytabs could not use.
        typer.echo("  Encrypting realm key...")
        crypto.encrypt_age(
            created.key_path.read_bytes(), admin_keys, repo.realm_key_path(realm))

        realm_config = realm_mod.RealmConfig(
            name=realm,
            etypes=etype_list,
            domains=[domain] if domain else [],
            kdc_role=kdc_role,
        )

        for princ_file in sorted(created.principals_path.glob("*.key")):
            typer.echo(f"  Encrypting principal: {princ_file.stem}")
            crypto.encrypt_age(
                princ_file.read_bytes(),
                admin_keys,
                principals_dir / f"{princ_file.stem}.age",
            )
            principal = realm_mod.principal_from_filename(princ_file.stem, {})
            realm_config.principals[principal] = realm_mod.classify(principal, realm)

        realm_mod.save(repo, realm_config)

    typer.secho(f"\nRealm {realm} initialized!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {realm_dir}")
    typer.echo(f"  Etypes:   {', '.join(etype_list)}")
    if domain:
        typer.echo(f"  Domain:   {domain}")
    typer.echo(f"\nNext steps:")
    typer.echo(f"  1. aegis init-role {kdc_role}                    # create the KDC role")
    typer.echo(f"  2. aegis add-host-to-role {kdc_role} <hostname>  # add the KDC host")
    if not domain:
        typer.echo(f"  3. aegis realm set {realm} --add-domain <domain>")
    typer.echo(f"  4. aegis build-keytabs")


@realm_app.command("import")
def realm_import(
    realm: str = typer.Argument(..., help="Realm name (e.g., SEA.FUDO.ORG)"),
    realm_key: Path = typer.Option(..., "--realm-key", help="Path to realm master key file"),
    principals_dir: Path = typer.Option(..., "--principals-dir", help="Directory containing principal key files"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="DNS domain this realm serves"),
):
    """Import an existing Kerberos realm and its principals."""
    repo = _repo(secrets_path)
    repo.ensure_structure()

    if not realm_key.exists():
        typer.echo(f"Error: Realm key not found: {realm_key}", err=True)
        raise typer.Exit(1)

    if not principals_dir.is_dir():
        typer.echo(f"Error: Principals directory not found: {principals_dir}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing Kerberos realm: {realm}")

    admin_keys = _admin_keys(repo)

    realm_dir = repo.realm_path(realm)
    realm_dir.mkdir(parents=True, exist_ok=True)
    principals_out = repo.realm_principals_path(realm)
    principals_out.mkdir(exist_ok=True)

    typer.echo("  Importing realm master key...")
    crypto.encrypt_age(realm_key.read_bytes(), admin_keys, repo.realm_key_path(realm))

    realm_config = realm_mod.load(repo, realm)
    if domain and domain not in realm_config.domains:
        realm_config.domains.append(domain)

    principal_files = sorted(principals_dir.glob("*.key"))
    if not principal_files:
        typer.echo("  Warning: No principal key files found (*.key)", err=True)

    typer.echo(f"  Importing {len(principal_files)} principal(s)...")
    for principal_file in principal_files:
        crypto.encrypt_age(
            principal_file.read_bytes(),
            admin_keys,
            principals_out / f"{principal_file.stem}.age",
        )
        principal = realm_mod.principal_from_filename(principal_file.stem, {})
        entry = realm_mod.classify(principal, realm)
        realm_config.principals.setdefault(principal, entry)
        if entry.kind == realm_mod.KIND_CROSS_REALM and entry.peer:
            if entry.peer not in realm_config.trusts:
                realm_config.trusts.append(entry.peer)
        typer.echo(f"    - {principal}")

    realm_mod.save(repo, realm_config)

    typer.secho(f"\nKerberos realm imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {realm_dir}")
    typer.echo(f"  Principals: {len(principal_files)}")
    if not realm_config.domains:
        typer.echo(f"\nDeclare the domains it serves before building keytabs:")
        typer.echo(f"  aegis realm set {realm} --add-domain <domain>")


@realm_app.command("list")
def realm_list(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """List realms with their domains, trusts and member hosts."""
    repo = _repo(secrets_path)

    realms = repo.list_realms()
    if not realms:
        typer.echo("No realms configured.")
        return

    grouped = realm_mod.hosts_by_realm(repo)

    for name in realms:
        realm_config = realm_mod.load(repo, name)
        principals = realm_mod.stored_principals(repo, name)
        members = grouped.get(name, [])

        typer.secho(f"\n{name}", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"  domains:    {', '.join(realm_config.domains) or '(none declared)'}")
        typer.echo(f"  trusts:     {', '.join(realm_config.trusts) or '(none)'}")
        typer.echo(f"  kdc role:   {realm_config.kdc_role}")
        typer.echo(f"  etypes:     {', '.join(realm_config.etypes)}")
        typer.echo(f"  principals: {len(principals)}")
        typer.echo(f"  hosts:      {len(members)}")

        if not realm_config.domains:
            typer.secho(
                "  ! no domains declared, so no host resolves to this realm",
                fg=typer.colors.YELLOW,
            )


@realm_app.command("show")
def realm_show(
    realm: str = typer.Argument(..., help="Realm name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Show a realm's principals, grouped by kind."""
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)

    typer.secho(f"{realm}", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"  domains:  {', '.join(realm_config.domains) or '(none declared)'}")
    typer.echo(f"  trusts:   {', '.join(realm_config.trusts) or '(none)'}")
    typer.echo(f"  kdc role: {realm_config.kdc_role}")
    typer.echo(f"  etypes:   {', '.join(realm_config.etypes)}")

    principals = realm_mod.stored_principals(repo, realm)
    by_kind: dict[str, list[str]] = {}
    for principal in principals:
        entry = realm_config.principals.get(principal) or realm_mod.classify(principal, realm)
        by_kind.setdefault(entry.kind, []).append(principal)

    for kind in (
        realm_mod.KIND_INFRASTRUCTURE,
        realm_mod.KIND_CROSS_REALM,
        realm_mod.KIND_HOST,
        realm_mod.KIND_SERVICE,
    ):
        names = sorted(by_kind.pop(kind, []))
        if not names:
            continue
        typer.echo(f"\n  {kind} ({len(names)}):")
        for name in names:
            typer.echo(f"    {name}")

    for kind, names in sorted(by_kind.items()):
        typer.echo(f"\n  {kind} ({len(names)}):")
        for name in sorted(names):
            typer.echo(f"    {name}")


@realm_app.command("set")
def realm_set(
    realm: str = typer.Argument(..., help="Realm name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    add_domain: list[str] = typer.Option([], "--add-domain", help="Declare a domain this realm serves"),
    remove_domain: list[str] = typer.Option([], "--remove-domain", help="Stop serving a domain"),
    kdc_role: Optional[str] = typer.Option(None, "--kdc-role", help="Role whose members run the KDC"),
    etypes: Optional[str] = typer.Option(None, "--etypes", help="Comma-separated encryption types"),
    max_ticket_lifetime: Optional[str] = typer.Option(None, "--max-ticket-lifetime"),
    max_renewable_lifetime: Optional[str] = typer.Option(None, "--max-renewable-lifetime"),
):
    """Update a realm's metadata.

    Declaring a domain is what makes hosts resolve to this realm: a host in
    the 'domain-<domain>' role belongs to whichever realm claims <domain>.
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)

    for domain in add_domain:
        owner = realm_mod.realm_of_domain(repo, domain)
        if owner and owner != realm:
            typer.echo(
                f"Error: domain {domain} is already served by realm {owner}", err=True)
            raise typer.Exit(1)
        if domain not in realm_config.domains:
            realm_config.domains.append(domain)

    for domain in remove_domain:
        if domain in realm_config.domains:
            realm_config.domains.remove(domain)

    if kdc_role:
        realm_config.kdc_role = kdc_role
    if etypes:
        realm_config.etypes = [e.strip() for e in etypes.split(",")]
    if max_ticket_lifetime:
        realm_config.max_ticket_lifetime = max_ticket_lifetime
    if max_renewable_lifetime:
        realm_config.max_renewable_lifetime = max_renewable_lifetime

    path = realm_mod.save(repo, realm_config)

    typer.secho(f"Updated {realm}", fg=typer.colors.GREEN)
    typer.echo(f"  domains:  {', '.join(realm_config.domains) or '(none)'}")
    typer.echo(f"  kdc role: {realm_config.kdc_role}")
    typer.echo(f"  config:   {path}")

    members = realm_mod.hosts_by_realm(repo).get(realm, [])
    typer.echo(f"  hosts now resolving to this realm: {len(members)}")


# =============================================================================
# Principals
# =============================================================================

@realm_app.command("add-principal")
def realm_add_principal(
    realm: str = typer.Argument(..., help="Realm name"),
    principal: str = typer.Argument(..., help="Principal, e.g. 'postgres/rama.sea.fudo.org'"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    password: Optional[str] = typer.Option(None, "--password", help="Set this password instead of a random key"),
    host: Optional[str] = typer.Option(None, "--host", help="Host whose keytab should include this principal"),
):
    """Add a principal to a realm.

    Use --host to record which host's keytab it belongs in; 'aegis
    build-keytabs' includes it when extracting that host's keytab.
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)
    admin_keys = _admin_keys(repo)

    if principal in realm_config.principals:
        typer.echo(f"Principal already recorded: {principal}")
        raise typer.Exit(1)

    stem = realm_mod.principal_filename(principal)
    if (repo.realm_principals_path(realm) / f"{stem}.age").exists():
        typer.echo(f"Principal key already stored: {stem}.age")
        raise typer.Exit(1)

    typer.echo(f"Adding {principal} to {realm}...")

    with _InstantiatedRealm(repo, realm) as inst:
        krb.add_principal(
            principal, inst.kdc_conf, inst.principals_dir,
            password=password, verbose=True,
        )
        out = inst.store_principal(principal, admin_keys)

    entry = realm_mod.classify(principal, realm)
    if host:
        entry.host = host
    realm_config.principals[principal] = entry
    realm_mod.save(repo, realm_config)

    typer.secho(f"Added principal: {principal}", fg=typer.colors.GREEN)
    typer.echo(f"  Stored: {out}")
    if host:
        typer.echo(f"  Will be included in {host}'s keytab")
        typer.echo(f"  Run: aegis build-keytabs --force --realm {realm}")


@realm_app.command("rekey-principal")
def realm_rekey_principal(
    realm: str = typer.Argument(..., help="Realm name"),
    principal: str = typer.Argument(..., help="Principal to rotate"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    password: Optional[str] = typer.Option(None, "--password", help="Set this password instead of a random key"),
    prune: bool = typer.Option(False, "--prune", help="Drop the retained previous key instead of rotating"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Rotate a principal's key, keeping the previous one for a grace period.

    A Kerberos keytab can hold several kvnos for the same principal, so a
    rotation does not have to be a hard cutover. This retains the pre-rotation
    key under principals/previous/, and 'aegis build-keytabs' emits keytabs
    carrying both. Services keep authenticating with the old key until they
    receive the new keytab.

    The rotation is finished by dropping the old key once every affected host
    has been redeployed:

        aegis realm rekey-principal REALM principal --prune

    'aegis check' reports principals with a retained key, so an unfinished
    rotation does not go unnoticed.
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)
    admin_keys = _admin_keys(repo)

    stem = realm_mod.principal_filename(principal)
    current = repo.realm_principals_path(realm) / f"{stem}.age"
    previous = repo.realm_previous_principals_path(realm) / f"{stem}.age"

    if prune:
        if not previous.exists():
            typer.echo(f"No retained previous key for {principal}")
            raise typer.Exit(1)
        if not yes:
            typer.secho(
                "Any host still holding only the old keytab will stop "
                "authenticating once this key is dropped.",
                fg=typer.colors.YELLOW,
            )
            if not typer.confirm(f"Drop the previous key for {principal}?"):
                raise typer.Abort()
        previous.unlink()
        typer.secho(f"Dropped previous key for {principal}", fg=typer.colors.GREEN)
        typer.echo(f"  Rebuild keytabs: aegis build-keytabs --force --realm {realm}")
        return

    if not current.exists():
        typer.echo(f"Principal not found: {principal} ({current})", err=True)
        raise typer.Exit(1)

    if previous.exists():
        typer.echo(
            f"A previous key for {principal} is already retained.\n"
            f"Finish that rotation first: "
            f"aegis realm rekey-principal {realm} {principal} --prune",
            err=True,
        )
        raise typer.Exit(1)

    affected = [
        m.hostname for m in realm_mod.memberships(repo)
        if principal.endswith(f"/{m.fqdn}")
    ]
    entry = realm_config.principals.get(principal)
    if entry and entry.host and entry.host not in affected:
        affected.append(entry.host)

    if not yes:
        typer.echo(f"Rotating {principal} in {realm}.")
        if affected:
            typer.echo(f"  Affects keytabs for: {', '.join(sorted(affected))}")
        typer.echo(
            "  The previous key is retained, so keytabs will carry both kvnos\n"
            "  until you --prune. Services keep working in the meantime.")
        if not typer.confirm("Rotate?"):
            raise typer.Abort()

    # Archive the current key before touching the database: the whole point is
    # that the old key survives the rotation.
    previous.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(crypto.decrypt_age_bytes(current), admin_keys, previous)
    typer.echo(f"  Retained previous key: {previous}")

    try:
        with _InstantiatedRealm(repo, realm) as inst:
            krb.rekey_principal(
                principal, inst.kdc_conf, inst.principals_dir,
                password=password, verbose=True,
            )
            inst.store_principal(principal, admin_keys)
    except Exception:
        # Leave no half-rotated state: the archive is only meaningful next to
        # a rotated current key.
        previous.unlink(missing_ok=True)
        raise

    typer.secho(f"\nRotated {principal}", fg=typer.colors.GREEN)
    typer.echo(f"  New key:      {current}")
    typer.echo(f"  Previous key: {previous} (retained)")
    typer.echo("")
    typer.echo("Next:")
    typer.echo(f"  1. aegis build-keytabs --force --realm {realm}")
    typer.echo("  2. deploy the affected hosts")
    typer.echo(f"  3. aegis realm rekey-principal {realm} {principal} --prune")


@realm_app.command("remove-principal")
def realm_remove_principal(
    realm: str = typer.Argument(..., help="Realm name"),
    principal: str = typer.Argument(..., help="Principal to remove"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Remove a principal from a realm.

    Deleting the stored key does not invalidate keytabs already deployed to
    hosts; anything holding the old key keeps working until it is redeployed.
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)

    stem = realm_mod.principal_filename(principal)
    key_file = repo.realm_principals_path(realm) / f"{stem}.age"

    if not key_file.exists() and principal not in realm_config.principals:
        typer.echo(f"Principal not found: {principal}", err=True)
        raise typer.Exit(1)

    if not yes:
        typer.secho(
            "Removing a principal does not revoke keytabs already deployed.\n"
            "Hosts holding the old key keep authenticating until redeployed.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm(f"Remove {principal} from {realm}?"):
            raise typer.Abort()

    if key_file.exists():
        key_file.unlink()
        typer.echo(f"  Removed: {key_file}")

    realm_config.principals.pop(principal, None)
    realm_mod.save(repo, realm_config)

    typer.secho(f"Removed {principal} from {realm}", fg=typer.colors.GREEN)
    typer.echo(f"  Rebuild affected keytabs: aegis build-keytabs --force --realm {realm}")


# =============================================================================
# Cross-realm trust
# =============================================================================

def _trust_principal(target: str, source: str) -> str:
    """The krbtgt principal granting `source` access to `target`."""
    return f"krbtgt/{target}@{source}"


def _establish_one_way(
    repo: config.SecretsRepo,
    source: str,
    target: str,
    admin_keys: list[str],
) -> str:
    """Create krbtgt/target@source and store it in *both* realms.

    Principals are stored as decrypted kadmin dump lines, which carry the
    fully-qualified principal name and its plaintext key material.  Both
    realms therefore need the very same line -- create it once, write it
    twice.  No key negotiation is involved.
    """
    principal = _trust_principal(target, source)
    stem = realm_mod.principal_filename(principal)

    with _InstantiatedRealm(repo, source) as inst:
        existing = inst.principals_dir / f"{stem}.key"
        if not existing.exists():
            krb.add_principal(principal, inst.kdc_conf, inst.principals_dir, verbose=True)
        line = (inst.principals_dir / f"{stem}.key").read_bytes()

    for realm_name in (source, target):
        out = repo.realm_principals_path(realm_name) / f"{stem}.age"
        out.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(line, admin_keys, out)

        realm_config = realm_mod.load(repo, realm_name)
        realm_config.principals[principal] = realm_mod.PrincipalEntry(
            kind=realm_mod.KIND_CROSS_REALM,
            peer=target if realm_name == source else source,
        )
        peer = target if realm_name == source else source
        if peer not in realm_config.trusts:
            realm_config.trusts.append(peer)
        realm_mod.save(repo, realm_config)

    return principal


@realm_app.command("trust")
def realm_trust(
    realm_a: str = typer.Argument(..., help="First realm"),
    realm_b: str = typer.Argument(..., help="Second realm"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    one_way: bool = typer.Option(False, "--one-way", help="Only let REALM_A's principals reach REALM_B"),
):
    """Establish cross-realm trust between two realms.

    Bidirectional by default: creates krbtgt/B@A and krbtgt/A@B, storing each
    in both realms so the two KDCs share the key.
    """
    repo = _repo(secrets_path)
    realm_mod.require_realm(repo, realm_a)
    realm_mod.require_realm(repo, realm_b)
    admin_keys = _admin_keys(repo)

    if realm_a == realm_b:
        typer.echo("Error: cannot establish trust between a realm and itself", err=True)
        raise typer.Exit(1)

    created = [_establish_one_way(repo, realm_a, realm_b, admin_keys)]
    if not one_way:
        created.append(_establish_one_way(repo, realm_b, realm_a, admin_keys))

    typer.secho(
        f"\nTrust established: {realm_a} {'->' if one_way else '<->'} {realm_b}",
        fg=typer.colors.GREEN,
    )
    for principal in created:
        typer.echo(f"  {principal} (stored in both realms)")
    typer.echo(f"\nRebuild the KDC bundles: aegis build-keytabs")


@realm_app.command("untrust")
def realm_untrust(
    realm_a: str = typer.Argument(..., help="First realm"),
    realm_b: str = typer.Argument(..., help="Second realm"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Remove cross-realm trust between two realms."""
    repo = _repo(secrets_path)
    realm_mod.require_realm(repo, realm_a)
    realm_mod.require_realm(repo, realm_b)

    principals = [
        _trust_principal(realm_b, realm_a),
        _trust_principal(realm_a, realm_b),
    ]

    if not yes:
        typer.secho(
            "Running KDCs keep honouring the old cross-realm key until they "
            "load a rebuilt principal bundle.",
            fg=typer.colors.YELLOW,
        )
        if not typer.confirm(f"Remove trust between {realm_a} and {realm_b}?"):
            raise typer.Abort()

    removed = 0
    for realm_name in (realm_a, realm_b):
        realm_config = realm_mod.load(repo, realm_name)
        for principal in principals:
            key_file = (
                repo.realm_principals_path(realm_name)
                / f"{realm_mod.principal_filename(principal)}.age"
            )
            if key_file.exists():
                key_file.unlink()
                removed += 1
            realm_config.principals.pop(principal, None)

        peer = realm_b if realm_name == realm_a else realm_a
        if peer in realm_config.trusts:
            realm_config.trusts.remove(peer)
        realm_mod.save(repo, realm_config)

    typer.secho(
        f"Removed trust between {realm_a} and {realm_b} ({removed} files)",
        fg=typer.colors.GREEN,
    )
    typer.echo("Rebuild the KDC bundles: aegis build-keytabs")


# =============================================================================
# Export
# =============================================================================

@realm_app.command("export")
def realm_export(
    realm: str = typer.Argument(..., help="Realm name"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Write the KDC principal bundle for a realm.

    Produces deploy/kdc/<REALM>-principals.age, encrypted for the realm's KDC
    role.  The aegis.kdc NixOS module decrypts it in phase 2 and merges it
    into the live database, preserving principals that exist only there.
    """
    repo = _repo(secrets_path)
    realm_config = realm_mod.require_realm(repo, realm)
    admin_keys = _admin_keys(repo)

    kdc_pub_path = repo.role_pubkey_path(realm_config.kdc_role)
    if not kdc_pub_path.exists():
        typer.echo(
            f"Error: role '{realm_config.kdc_role}' has no public key at {kdc_pub_path}",
            err=True,
        )
        typer.echo(f"Create it with: aegis init-role {realm_config.kdc_role}", err=True)
        raise typer.Exit(1)

    kdc_pubkey = kdc_pub_path.read_text().strip()

    principals_dir = repo.realm_principals_path(realm)
    principal_files = sorted(principals_dir.glob("*.age")) if principals_dir.is_dir() else []
    if not principal_files:
        typer.echo(f"No principals stored for {realm}", err=True)
        raise typer.Exit(1)

    bundle = b"".join(crypto.decrypt_age_bytes(f) for f in principal_files)

    out = repo.kdc_deploy_path() / f"{realm}-principals.age"
    out.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(bundle, [kdc_pubkey, *admin_keys], out)

    # The KDC also needs the realm master key: without it the database it
    # builds cannot be encrypted, so a principal bundle on its own is useless.
    # In the repo the realm key is admin-only, so re-encrypt a copy here
    # rather than widening the source of truth.
    realm_key_out = repo.kdc_deploy_path() / f"{realm}-realm-key.age"
    crypto.encrypt_age(
        crypto.decrypt_age_bytes(repo.realm_key_path(realm)),
        [kdc_pubkey, *admin_keys],
        realm_key_out,
    )

    typer.secho(f"Exported {len(principal_files)} principals", fg=typer.colors.GREEN)
    typer.echo(f"  Principals: {out}")
    typer.echo(f"  Realm key:  {realm_key_out}")
    typer.echo(f"  Readable by: role {realm_config.kdc_role} + admin")
