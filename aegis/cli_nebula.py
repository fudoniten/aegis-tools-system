"""``aegis nebula`` — Nebula overlay network management."""

from pathlib import Path
from typing import Annotated, Optional

import typer

from . import config, crypto, host_secrets
from . import nebula as nebula_mod
from .errors import AegisError, MissingHostKeyError

nebula_app = typer.Typer(
    name="nebula",
    help="Manage Nebula overlay networks: the CA, addresses and certificates.",
    no_args_is_help=True,
)


def _repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    from .cli import get_secrets_repo
    return get_secrets_repo(secrets_path)


def _admin_keys(repo: config.SecretsRepo) -> list[str]:
    from .cli import admin_recipients
    return admin_recipients(repo)


def _only_network(repo: config.SecretsRepo, network: Optional[str]) -> str:
    """Resolve the network to act on, defaulting when there is only one."""
    if network:
        return network
    networks = nebula_mod.list_networks(repo)
    if not networks:
        raise AegisError(
            "No Nebula network exists. Create one with "
            "'aegis nebula init <name> --cidr <cidr>'."
        )
    if len(networks) > 1:
        raise AegisError(
            f"Several networks exist ({', '.join(networks)}); name one with --network."
        )
    return networks[0]


@nebula_app.command("init")
def nebula_init(
    network: Annotated[str, typer.Argument(help="Network name, e.g. 'fudo'")],
    cidr: Annotated[str, typer.Option("--cidr", help="Overlay range, e.g. 10.200.0.0/16")],
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    port: Annotated[int, typer.Option("--port", help="UDP port lighthouses listen on")] = nebula_mod.DEFAULT_PORT,
    ca_duration: Annotated[str, typer.Option("--ca-duration")] = nebula_mod.DEFAULT_CA_DURATION,
    cert_duration: Annotated[str, typer.Option("--cert-duration")] = nebula_mod.DEFAULT_CERT_DURATION,
    cert_version: Annotated[Optional[int], typer.Option("--cert-version", help="Certificate format: 2, or 1 for older clients. Defaults to the newest this nebula-cert supports")] = None,
):
    """Create a Nebula network and mint its CA.

    The CA private key is encrypted to the admin recipient set and to nothing
    else — never to a host, never to a role. It is the one piece of material
    that can mint any identity on the mesh, so anyone holding an admin key can
    forge membership. Treat 'aegis admin add-key' with that in mind.

    Run once per network. There is no un-minting: a replaced CA orphans every
    certificate it ever signed.

    --cert-version is likewise permanent: signing inherits the CA's version.
    Version 2 gives IPv6 and multiple addresses per certificate but needs
    Nebula 1.10+ at both ends; version 1 is IPv4-only and read by everything.
    It defaults to the newest this nebula-cert can produce. Choose 1 if
    anything on the mesh might run an older Nebula than the machine minting
    the CA — the mobile clients being the usual reason.
    \b
    Examples:
        aegis nebula init fudo --cidr 10.200.0.0/16
        aegis nebula init fudo --cidr 10.200.0.0/16 --cert-version 1
    """
    repo = _repo(secrets_path)

    if nebula_mod.list_networks(repo) and network in nebula_mod.list_networks(repo):
        raise AegisError(f"Network '{network}' already exists")

    # Ask the tool rather than assuming: nebula-cert only learned to make v2
    # certificates in 1.10, and this may not be that.
    if cert_version is None:
        cert_version = nebula_mod.default_cert_version()

    cfg = nebula_mod.NetworkConfig(
        name=network,
        cidr=cidr,
        port=port,
        ca_duration=ca_duration,
        cert_duration=cert_duration,
        cert_version=cert_version,
    )
    if cert_version not in (1, 2):
        raise AegisError(f"Unknown certificate version {cert_version}; use 1 or 2")
    # Validate the CIDR before anything is written.
    _ = cfg.network

    admin_keys = _admin_keys(repo)
    key_path, cert_path = nebula_mod.create_ca(repo, cfg, admin_keys)
    config_path = nebula_mod.save_network(repo, cfg)

    typer.echo(f"Created Nebula network '{network}' ({cidr})")
    typer.echo(f"  certificate format: version {cert_version}"
               + ("" if cert_version == 2 else
                  "  (IPv4 only; readable by every Nebula release)"))
    typer.echo(f"  {config_path}")
    typer.echo(f"  {key_path}   encrypted to {len(admin_keys)} admin key(s)")
    typer.echo(f"  {cert_path}  public")
    typer.echo()
    typer.echo("Add hosts with 'aegis nebula add-host', then 'aegis build nebula'.")


@nebula_app.command("set-site-range")
def nebula_set_site_range(
    site: Annotated[str, typer.Argument(help="Site name, as in fudo-entities")],
    cidr: Annotated[str, typer.Argument(help="Range to allocate that site's addresses from")],
    network: Optional[str] = typer.Option(None, "--network", "-N"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Draw a site's addresses from a particular range.

    Purely an allocation convenience, so that reading an address tells you
    where the host was when it was assigned. It has no routing meaning:
    certificates are always issued with the *network* prefix, because that is
    what tells a host which addresses reach over the tun device.
    """
    repo = _repo(secrets_path)
    net = _only_network(repo, network)
    cfg = nebula_mod.load_network(repo, net)
    cfg.site_ranges[site] = cidr
    nebula_mod.save_network(repo, cfg)
    typer.echo(f"{net}: {site} allocates from {cidr}")


@nebula_app.command("add-host")
def nebula_add_host(
    hostname: Annotated[str, typer.Argument(help="Host to put on the mesh")],
    network: Optional[str] = typer.Option(None, "--network", "-N"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    address: Annotated[Optional[str], typer.Option("--address", help="Overlay address; allocated if omitted")] = None,
    site: Annotated[Optional[str], typer.Option("--site", help="Allocate from this site's range")] = None,
    groups: Annotated[Optional[str], typer.Option("--groups", help="Comma-separated certificate groups")] = None,
    lighthouse: Annotated[bool, typer.Option("--lighthouse", help="This host is a lighthouse and a relay")] = False,
    endpoint: Annotated[Optional[list[str]], typer.Option("--endpoint", help="Lighthouse public host:port; repeatable")] = None,
    local_key: Annotated[bool, typer.Option("--local-key", help="Host keeps its own private key; Aegis signs only")] = False,
):
    """Give a host an address and groups on the mesh.

    Records intent only — no key material is generated here. 'aegis build
    nebula' does that for every host that lacks it.

    --local-key is for a host whose private key should never exist centrally:
    it generates the pair itself, sends the public half (see 'aegis nebula
    import-pubkey'), and Aegis signs a certificate without ever holding a key.
    That is also the path for a host you cannot deploy to yet, since it needs
    no deploy to complete.
    \b
    Examples:
        aegis nebula add-host nostromo --site seattle --groups server
        aegis nebula add-host procul --lighthouse --endpoint 172.86.179.18:4242
        aegis nebula add-host laptop --site mobile --local-key
    """
    repo = _repo(secrets_path)
    net = _only_network(repo, network)
    cfg = nebula_mod.load_network(repo, net)

    existing = nebula_mod.all_hosts(repo, net)
    if hostname in existing:
        raise AegisError(
            f"{hostname} is already on '{net}' at {existing[hostname].address}"
        )

    if address is None:
        address = nebula_mod.allocate_address(
            cfg, taken={e.address for e in existing.values()}, site=site
        )

    group_list = [g.strip() for g in (groups or "").split(",") if g.strip()]
    if lighthouse and "lighthouse" not in group_list:
        group_list.append("lighthouse")

    entry = nebula_mod.HostEntry(
        hostname=hostname,
        address=address,
        groups=group_list,
        lighthouse=lighthouse,
        endpoints=list(endpoint or []),
        local_key=local_key,
    )
    nebula_mod.assert_unique({**existing, hostname: entry})
    path = nebula_mod.save_host(repo, net, entry)

    typer.echo(f"{hostname}: {address}/{cfg.prefix_length} on '{net}'")
    if group_list:
        typer.echo(f"  groups: {', '.join(group_list)}")
    if lighthouse and not entry.endpoints:
        typer.secho(
            "  warning: a lighthouse with no --endpoint cannot be found by "
            "anyone. Add one before building.",
            fg=typer.colors.YELLOW,
        )
    if local_key:
        typer.echo(f"  key stays on the host; import its public key before building")
    typer.echo(f"  {path}")


@nebula_app.command("import-pubkey")
def nebula_import_pubkey(
    hostname: Annotated[str, typer.Argument()],
    pubkey: Annotated[Path, typer.Argument(help="File holding the host's Nebula public key")],
    network: Optional[str] = typer.Option(None, "--network", "-N"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Take in a public key from a host that keeps its own private key.

    The host runs 'nebula-enroll keygen' and sends the public half — which is
    public, so it can travel by paste, mail or a photo of a QR code. Its
    private key never leaves it and never exists here.
    """
    repo = _repo(secrets_path)
    net = _only_network(repo, network)

    entry = nebula_mod.load_host(repo, net, hostname)
    if entry is None:
        raise AegisError(
            f"{hostname} is not on '{net}'. Add it first with 'aegis nebula add-host'."
        )
    if not pubkey.exists():
        raise AegisError(f"No such file: {pubkey}")

    dest = repo.nebula_host_pubkey_path(net, hostname)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(pubkey.read_bytes())

    if not entry.local_key:
        entry.local_key = True
        nebula_mod.save_host(repo, net, entry)
        typer.echo(f"{hostname}: marked as keeping its own key")

    typer.echo(f"Imported {dest}")
    typer.echo("Run 'aegis build nebula' to sign it.")


@nebula_app.command("list")
def nebula_list(
    network: Optional[str] = typer.Option(None, "--network", "-N"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Show the host table for a network, with certificate expiry."""
    from datetime import datetime, timezone

    repo = _repo(secrets_path)
    net = _only_network(repo, network)
    cfg = nebula_mod.load_network(repo, net)
    hosts = nebula_mod.all_hosts(repo, net)

    typer.echo(f"{net}  {cfg.cidr}  port {cfg.port}")
    typer.echo()
    typer.echo(f"{'HOST':<18} {'ADDRESS':<16} {'LIGHT':<6} {'KEY':<7} {'EXPIRES':<12} GROUPS")

    now = datetime.now(timezone.utc)
    for hostname, entry in sorted(hosts.items()):
        cert = repo.nebula_host_deploy_path(hostname, net) / f"{net}.crt"
        if cert.exists():
            try:
                days = (nebula_mod.cert_expiry(cert) - now).days
                expires = f"{days}d" if days >= 0 else "EXPIRED"
            except nebula_mod.NebulaError:
                expires = "unreadable"
        else:
            expires = "-"
        typer.echo(
            f"{hostname:<18} {entry.address:<16} "
            f"{'yes' if entry.lighthouse else '-':<6} "
            f"{'local' if entry.local_key else 'aegis':<7} "
            f"{expires:<12} {','.join(entry.groups)}"
        )


@nebula_app.command("fingerprint")
def nebula_fingerprint(
    hostname: Annotated[str, typer.Argument()],
    network: Optional[str] = typer.Option(None, "--network", "-N"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Print a host's certificate fingerprint, for the Nebula blocklist.

    This is the revocation path for a key Aegis cannot rotate — a host that
    generated its own. Blocklisting takes full effect only once every host has
    the new list, so treat it as a fleet-wide deploy.
    """
    repo = _repo(secrets_path)
    net = _only_network(repo, network)
    cert = repo.nebula_host_deploy_path(hostname, net) / f"{net}.crt"
    if not cert.exists():
        raise AegisError(f"No certificate for {hostname} on '{net}' at {cert}")
    typer.echo(nebula_mod.cert_fingerprint(cert))


def build_nebula(
    secrets_path: Optional[Path] = None,
    dry_run: bool = False,
    network: Optional[str] = None,
    renew_within: int = nebula_mod.DEFAULT_RENEW_WITHIN_DAYS,
    rotate: bool = False,
) -> None:
    """Sign certificates and generate keys for hosts that need them.

    Unlike every other generator here, this is not purely "create if missing".
    Nebula certificates expire, so a certificate with less than ``renew_within``
    days left is re-signed against the existing key. Renewal keeps the key and
    so is invisible to the mesh; only ``rotate`` mints new key material, which
    drops the host until it is deployed again.
    """
    from .cli import get_secrets_repo, get_host_age_pubkey, host_placement

    repo = get_secrets_repo(secrets_path)
    networks = [network] if network else nebula_mod.list_networks(repo)
    if not networks:
        typer.echo("No Nebula networks configured. Use 'aegis nebula init' first.")
        return

    admin_keys = _admin_keys(repo)

    for net in networks:
        cfg = nebula_mod.load_network(repo, net)
        hosts = nebula_mod.all_hosts(repo, net)
        if not hosts:
            typer.echo(f"  {net}: no hosts on this network yet")
            continue

        nebula_mod.assert_unique(hosts)

        lighthouses = list(nebula_mod.iter_lighthouses(hosts))
        if not lighthouses:
            typer.secho(
                f"  {net}: no lighthouse — hosts will have no way to find each other",
                fg=typer.colors.YELLOW,
            )
        for name, entry in lighthouses:
            if not entry.endpoints:
                typer.secho(
                    f"  {net}: lighthouse {name} has no endpoint and cannot be reached",
                    fg=typer.colors.YELLOW,
                )

        ca_cert = repo.nebula_ca_cert_path(net)
        deploying = set(repo.list_deploying_hosts())
        pending: list[tuple[str, nebula_mod.HostEntry, str]] = []

        for hostname, entry in sorted(hosts.items()):
            cert_path = repo.nebula_host_deploy_path(hostname, net) / f"{net}.crt"

            if rotate:
                reason = "rotating"
            elif not cert_path.exists():
                reason = "no certificate"
            else:
                try:
                    if nebula_mod.needs_renewal(cert_path, renew_within):
                        reason = "expiring"
                    else:
                        continue
                except nebula_mod.NebulaError:
                    reason = "unreadable certificate"

            if entry.local_key and not repo.nebula_host_pubkey_path(net, hostname).exists():
                typer.echo(
                    f"  {hostname}: keeps its own key, but no public key has been "
                    f"imported — skipping (see 'aegis nebula import-pubkey')"
                )
                continue

            if hostname not in deploying and not entry.local_key:
                typer.echo(f"  {hostname}: not a deploying host — skipping")
                continue

            pending.append((hostname, entry, reason))

        if not pending:
            typer.echo(f"  {net}: every certificate is current")
        elif dry_run:
            for hostname, entry, reason in pending:
                typer.echo(f"  [dry-run] Would sign {hostname} ({reason})")
        else:
            with nebula_mod.CaMaterial(repo, net) as ca:
                for hostname, entry, reason in pending:
                    _build_one(
                        repo, cfg, ca, entry, reason,
                        rotate=rotate,
                        admin_keys=admin_keys,
                        ca_cert=ca_cert,
                        placement=host_placement(repo, hostname, f"secret:nebula-{net}-key"),
                        get_host_age_pubkey=get_host_age_pubkey,
                    )

        if not dry_run:
            path = nebula_mod.save_network_json(repo, cfg, hosts)
            typer.echo(f"  {net}: wrote {path}")


def _build_one(
    repo: config.SecretsRepo,
    cfg: nebula_mod.NetworkConfig,
    ca: nebula_mod.CaMaterial,
    entry: nebula_mod.HostEntry,
    reason: str,
    *,
    rotate: bool,
    admin_keys: list[str],
    ca_cert: Path,
    placement: config.Placement,
    get_host_age_pubkey,
) -> None:
    hostname = entry.hostname

    # Resolve recipients before signing, so a host that cannot be encrypted
    # for is skipped without leaving a certificate behind that nothing
    # references.
    #
    # A host that keeps its own key may not be initialised in Aegis at all --
    # that is the point of the path. Everything Aegis holds for it is public,
    # so the admin set alone is enough, and the certificate travels back out of
    # band. A host whose key Aegis generates has nowhere to send it without a
    # master key, so that is a genuine skip.
    try:
        recipients = [get_host_age_pubkey(hostname, repo), *admin_keys]
    except MissingHostKeyError as exc:
        if not entry.local_key:
            typer.echo(f"    Skipping {hostname}: {exc}", err=True)
            return
        recipients = list(admin_keys)

    typer.echo(f"  Signing {hostname} ({reason})...")

    out_dir = repo.nebula_host_deploy_path(hostname, cfg.name)
    existing_pub = out_dir / f"{cfg.name}.pub"

    # Which public key to sign. A host that keeps its own key has submitted
    # one; otherwise, an existing public key means this is a renewal and the
    # host's identity must survive it. Only a rotation, or a host with no key
    # at all, mints a new pair.
    if entry.local_key:
        pubkey_path = repo.nebula_host_pubkey_path(cfg.name, hostname)
    elif rotate:
        pubkey_path = None
    elif existing_pub.exists():
        pubkey_path = existing_pub
    else:
        pubkey_path = None

    signed = nebula_mod.sign_host(ca, cfg, entry, pubkey_path=pubkey_path)

    out_dir.mkdir(parents=True, exist_ok=True)
    existing_pub.write_bytes(signed.pub_pem)

    # The plaintext certificate stays beside the ciphertext: it is public, and
    # keeping it readable is what lets 'aegis nebula list' report expiry
    # without an admin key.
    (out_dir / f"{cfg.name}.crt").write_bytes(signed.cert_pem)

    if signed.key_pem is not None:
        crypto.encrypt_age(signed.key_pem, recipients, out_dir / f"{cfg.name}.key.age")

    crypto.encrypt_age(signed.cert_pem, recipients, out_dir / f"{cfg.name}.crt.age")
    crypto.encrypt_age(ca_cert.read_bytes(), recipients, out_dir / f"{cfg.name}-ca.crt.age")

    manifest = host_secrets.load_host_manifest(repo.deploy_path, hostname)
    manifest.secrets.update(
        host_secrets.make_nebula_entries(
            cfg.name,
            # Whether the host has a key here at all -- NOT whether this run
            # generated one. A renewal mints nothing and must still leave the
            # existing key's entry in place.
            with_key=not entry.local_key,
            placement=placement,
        )
    )
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    expiry = nebula_mod.cert_expiry(out_dir / f"{cfg.name}.crt")
    typer.echo(f"    {entry.address}/{cfg.prefix_length}, expires {expiry.date()}")
