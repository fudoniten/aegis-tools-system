"""Nebula overlay network: CA custody, address allocation, certificate signing.

A Nebula network is structurally a Kerberos realm: shared signing material held
by the admin, minting per-host artifacts.  It is modelled the same way.

::

    src/nebula/networks/<net>/network.toml     what the network is
    src/nebula/networks/<net>/ca.key.age       encrypted to admins ONLY
    src/nebula/networks/<net>/ca.crt           plaintext; public
    src/nebula/networks/<net>/hosts/<h>.toml   address and groups
    src/nebula/networks/<net>/pubkeys/<h>.pub  for hosts that keep their own key

    deploy/hosts/<h>/nebula/<net>.key.age      encrypted to host + admins
    deploy/hosts/<h>/nebula/<net>.crt.age      the host's certificate
    deploy/hosts/<h>/nebula/<net>-ca.crt.age   the CA certificate
    deploy/nebula/<net>/network.json           plaintext; read by nixos-config

Two things are worth knowing about the layout.

The certificate and the CA certificate are **public** — they carry an address,
groups and an expiry, and are useless without the private key — yet they are
encrypted like everything else.  That is deliberate: the Aegis NixOS module
decrypts every manifest entry, so shipping these as ciphertext means Nebula
needs no new mechanism on the host side at all.  Encrypting public data costs
nothing; a second delivery path would cost a great deal.

``network.json`` is the exception, and is plaintext: nixos-config reads it at
evaluation time to build the lighthouse list and static host map, and Nix
cannot decrypt.  It holds only addresses and public endpoints.
"""

import functools
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore

from . import crypto
from .config import SecretsRepo
from .errors import AegisError

#: Nebula's own default, and the port a lighthouse must be reachable on.
DEFAULT_PORT = 4242

#: A CA that outlives its certificates by a wide margin is what makes rotation
#: a choice rather than an emergency.
DEFAULT_CA_DURATION = "43800h"      # ~5 years
DEFAULT_CERT_DURATION = "8760h"     # 1 year

#: Re-sign a certificate once it has this little life left.  Unlike every
#: other generator in this repo, Nebula certificates expire, so "create if
#: missing" is not enough on its own.
DEFAULT_RENEW_WITHIN_DAYS = 30

#: Certificate format, for a network whose config predates the field.  The
#: version is decided once when the CA is minted and cannot be changed
#: afterwards -- ``sign`` inherits it, and every certificate the CA signs
#: carries it.  A network created without the field was necessarily made by a
#: nebula-cert that only knew v1.
#:
#: Version 2 brings IPv6 and multiple addresses per certificate, and needs
#: Nebula 1.10 or later at both ends.  Version 1 is IPv4-only but is read by
#: everything -- the right choice if anything on the mesh might run an older
#: Nebula than the fleet's nixpkgs pin, the iOS and Android clients being the
#: usual reason.
#:
#: What a *new* network gets when nothing is specified comes from
#: :func:`default_cert_version`, which asks the tool rather than assuming.
LEGACY_CERT_VERSION = 1


class NebulaError(AegisError):
    """Raised for Nebula network problems."""


@dataclass
class NetworkConfig:
    """Contents of ``network.toml``."""

    name: str
    cidr: str
    port: int = DEFAULT_PORT
    ca_duration: str = DEFAULT_CA_DURATION
    cert_duration: str = DEFAULT_CERT_DURATION
    #: Fixed when the CA is minted; see :data:`LEGACY_CERT_VERSION` and
    #: :func:`default_cert_version`.
    cert_version: int = LEGACY_CERT_VERSION
    #: Allocation convenience only: site -> CIDR to draw addresses from.  It
    #: has no routing meaning; every certificate is issued with the *network*
    #: prefix (see :meth:`prefix_length`), because that prefix is what tells a
    #: host which addresses are reachable over the tun device.  Issuing a site
    #: prefix instead would leave every other site off-net.
    site_ranges: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "cidr": self.cidr,
            "port": self.port,
            "ca_duration": self.ca_duration,
            "cert_duration": self.cert_duration,
            "cert_version": self.cert_version,
        }
        if self.site_ranges:
            d["site_ranges"] = dict(self.site_ranges)
        return d

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "NetworkConfig":
        return cls(
            name=name,
            cidr=data["cidr"],
            port=data.get("port", DEFAULT_PORT),
            ca_duration=data.get("ca_duration", DEFAULT_CA_DURATION),
            cert_duration=data.get("cert_duration", DEFAULT_CERT_DURATION),
            cert_version=int(data.get("cert_version", LEGACY_CERT_VERSION)),
            site_ranges=dict(data.get("site_ranges", {})),
        )

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def prefix_length(self) -> int:
        return self.network.prefixlen


@dataclass
class HostEntry:
    """Contents of ``hosts/<hostname>.toml``."""

    hostname: str
    address: str
    groups: list[str] = field(default_factory=list)
    lighthouse: bool = False
    #: Lighthouses only: ``host:port`` reachable from anywhere.
    endpoints: list[str] = field(default_factory=list)
    #: When true, the private key is generated on the host and never held
    #: here.  Aegis still allocates the address and signs the certificate; it
    #: signs from ``pubkeys/<hostname>.pub``, and deploys no key.
    local_key: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"address": self.address}
        if self.groups:
            d["groups"] = list(self.groups)
        if self.lighthouse:
            d["lighthouse"] = True
        if self.endpoints:
            d["endpoints"] = list(self.endpoints)
        if self.local_key:
            d["local_key"] = True
        return d

    @classmethod
    def from_dict(cls, hostname: str, data: dict) -> "HostEntry":
        return cls(
            hostname=hostname,
            address=data["address"],
            groups=list(data.get("groups", [])),
            lighthouse=bool(data.get("lighthouse", False)),
            endpoints=list(data.get("endpoints", [])),
            local_key=bool(data.get("local_key", False)),
        )


# ---------------------------------------------------------------------------
# Repo access
# ---------------------------------------------------------------------------


def list_networks(repo: SecretsRepo) -> list[str]:
    root = repo.nebula_networks_path
    if not root.exists():
        return []
    return sorted(d.name for d in root.iterdir() if d.is_dir())


def load_network(repo: SecretsRepo, net: str) -> NetworkConfig:
    path = repo.nebula_network_path(net) / "network.toml"
    if not path.exists():
        raise NebulaError(
            f"No Nebula network '{net}'. Create it with 'aegis nebula init {net} --cidr ...'."
        )
    with open(path, "rb") as f:
        return NetworkConfig.from_dict(net, tomllib.load(f))


def save_network(repo: SecretsRepo, cfg: NetworkConfig) -> Path:
    path = repo.nebula_network_path(cfg.name) / "network.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        tomli_w.dump(cfg.to_dict(), f)
    return path


def list_hosts(repo: SecretsRepo, net: str) -> list[str]:
    hosts_dir = repo.nebula_hosts_path(net)
    if not hosts_dir.exists():
        return []
    return sorted(f.stem for f in hosts_dir.glob("*.toml"))


def load_host(repo: SecretsRepo, net: str, hostname: str) -> HostEntry | None:
    path = repo.nebula_host_config_path(net, hostname)
    if not path.exists():
        return None
    with open(path, "rb") as f:
        return HostEntry.from_dict(hostname, tomllib.load(f))


def save_host(repo: SecretsRepo, net: str, entry: HostEntry) -> Path:
    path = repo.nebula_host_config_path(net, entry.hostname)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        tomli_w.dump(entry.to_dict(), f)
    return path


def all_hosts(repo: SecretsRepo, net: str) -> dict[str, HostEntry]:
    out: dict[str, HostEntry] = {}
    for hostname in list_hosts(repo, net):
        entry = load_host(repo, net, hostname)
        if entry is not None:
            out[hostname] = entry
    return out


# ---------------------------------------------------------------------------
# Address allocation
# ---------------------------------------------------------------------------


def allocate_address(
    cfg: NetworkConfig,
    taken: set[str],
    site: str | None = None,
) -> str:
    """Lowest free address, preferring the host's site range.

    A site with no range of its own — or a range that has filled up — falls
    back to the network at large, so allocation never fails just because the
    site table is incomplete.  Addresses are never reused: see
    :func:`assert_unique`.
    """
    pools: list[ipaddress.IPv4Network] = []
    if site and site in cfg.site_ranges:
        pools.append(ipaddress.ip_network(cfg.site_ranges[site], strict=False))
    pools.append(cfg.network)

    for pool in pools:
        for candidate in pool.hosts():
            if str(candidate) not in taken:
                return str(candidate)

    raise NebulaError(f"No free address left in {cfg.cidr}")


def assert_unique(hosts: dict[str, HostEntry]) -> None:
    """Two hosts on one address is a routing coin-flip, not an error Nebula
    reports.  Catch it here instead."""
    seen: dict[str, str] = {}
    for hostname, entry in sorted(hosts.items()):
        if entry.address in seen:
            raise NebulaError(
                f"{hostname} and {seen[entry.address]} are both assigned "
                f"{entry.address}"
            )
        seen[entry.address] = hostname


# ---------------------------------------------------------------------------
# nebula-cert
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _cert_capabilities() -> frozenset[str]:
    """Which flags this ``nebula-cert`` understands.

    The CLI changed shape in Nebula 1.10, when the v2 certificate format
    arrived: ``sign -ip`` became ``sign -networks`` (a list, since a v2
    certificate can carry several addresses), and ``ca`` gained ``-version``.

    Probing rather than assuming keeps this working against whichever Nebula
    the admin's machine happens to have -- which is not necessarily the one the
    fleet runs, and not necessarily the one this flake pins.
    """
    caps: set[str] = set()
    for mode, flags in (("ca", ("version", )), ("sign", ("networks", ))):
        try:
            result = subprocess.run(
                ["nebula-cert", mode, "-h"], capture_output=True, text=True
            )
        except FileNotFoundError as exc:
            raise NebulaError(
                "nebula-cert not found. It comes from the 'nebula' package; the "
                "aegis wrapper puts it on PATH."
            ) from exc
        # -h writes usage to stderr on some versions and stdout on others.
        text = result.stdout + result.stderr
        for flag in flags:
            if f"-{flag}" in text:
                caps.add(f"{mode}:{flag}")
    return frozenset(caps)


def supports_cert_v2() -> bool:
    """Whether this nebula-cert can mint version 2 certificates (1.10+)."""
    return "ca:version" in _cert_capabilities()


def default_cert_version() -> int:
    """The newest certificate format this nebula-cert can produce."""
    return 2 if supports_cert_v2() else 1


def _networks_flag() -> str:
    return "-networks" if "sign:networks" in _cert_capabilities() else "-ip"


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise NebulaError(
            "nebula-cert not found. It comes from the 'nebula' package; the "
            "aegis wrapper puts it on PATH."
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise NebulaError(
            f"{' '.join(cmd[:2])} failed: {exc.stderr.strip() or exc.stdout.strip()}"
        ) from exc
    return result.stdout


def cert_details(cert_path: Path) -> dict[str, Any]:
    """Parsed certificate.

    ``print -json`` emits a bare object up to Nebula 1.9 and an array from 1.10
    onwards, where one file may hold a bundle.  Either way this wants the first
    certificate in it.
    """
    out = _run(["nebula-cert", "print", "-path", str(cert_path), "-json"])
    parsed = json.loads(out)
    if isinstance(parsed, list):
        if not parsed:
            raise NebulaError(f"No certificate in {cert_path}")
        return parsed[0]
    return parsed


#: Go marshals ``time.Time`` as RFC3339 *Nano*, which can carry nine digits of
#: fractional seconds.  :func:`datetime.fromisoformat` accepts at most six.
_FRACTIONAL_SECONDS = re.compile(r"\.(\d+)")


def _parse_rfc3339(raw: str) -> datetime:
    trimmed = _FRACTIONAL_SECONDS.sub(lambda m: "." + m.group(1)[:6], raw)
    return datetime.fromisoformat(trimmed.replace("Z", "+00:00"))


def cert_expiry(cert_path: Path) -> datetime:
    return _parse_rfc3339(cert_details(cert_path)["details"]["notAfter"])


def cert_fingerprint(cert_path: Path) -> str:
    return cert_details(cert_path)["fingerprint"]


def needs_renewal(cert_path: Path, within_days: int) -> bool:
    remaining = cert_expiry(cert_path) - datetime.now(timezone.utc)
    return remaining.days < within_days


class CaMaterial:
    """The CA key and certificate, decrypted into a throwaway directory.

    The private key exists in plaintext only inside this context, only on the
    admin's machine, and only for as long as a signing run takes.  It is never
    written into the repo unencrypted and never leaves for a host.
    """

    def __init__(self, repo: SecretsRepo, net: str):
        self.repo = repo
        self.net = net
        self._dir: Path | None = None

    def __enter__(self) -> "CaMaterial":
        key_age = self.repo.nebula_ca_key_path(self.net)
        crt = self.repo.nebula_ca_cert_path(self.net)
        if not key_age.exists():
            raise NebulaError(
                f"No CA for network '{self.net}'. Run 'aegis nebula init {self.net}'."
            )
        if not crt.exists():
            raise NebulaError(f"Network '{self.net}' has a CA key but no ca.crt")

        self._dir = Path(tempfile.mkdtemp(prefix=f"aegis-nebula-{self.net}-"))
        self.key_path = self._dir / "ca.key"
        self.cert_path = self._dir / "ca.crt"
        self.key_path.write_bytes(crypto.decrypt_age_bytes(key_age))
        self.key_path.chmod(0o600)
        self.cert_path.write_bytes(crt.read_bytes())
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None


def create_ca(
    repo: SecretsRepo,
    cfg: NetworkConfig,
    admin_keys: list[str],
) -> tuple[Path, Path]:
    """Mint a CA, encrypting the private half to the admin set.

    Returns ``(ca.key.age, ca.crt)``.  Refuses to overwrite: a replaced CA
    orphans every certificate already signed by it.
    """
    key_age = repo.nebula_ca_key_path(cfg.name)
    crt = repo.nebula_ca_cert_path(cfg.name)
    if key_age.exists():
        raise NebulaError(
            f"Network '{cfg.name}' already has a CA at {key_age}. Replacing it "
            f"would orphan every certificate signed so far. To rotate, create "
            f"the new CA under a new network name and concatenate its ca.crt "
            f"into the trusted bundle while both are in use."
        )
    if not admin_keys:
        raise NebulaError("No admin recipients; refusing to mint an unrecoverable CA")

    if cfg.cert_version == 2 and not supports_cert_v2():
        raise NebulaError(
            "this nebula-cert cannot create version 2 certificates -- the "
            "-version flag arrived in Nebula 1.10, and this one does not have "
            "it.\n"
            "Either upgrade Nebula, or create the network with "
            "--cert-version 1, which is IPv4-only but understood by every "
            "release. The choice is permanent: signing inherits the CA's "
            "version."
        )

    with tempfile.TemporaryDirectory(prefix="aegis-nebula-ca-") as tmp:
        tmp_path = Path(tmp)
        tmp_key = tmp_path / "ca.key"
        tmp_crt = tmp_path / "ca.crt"
        cmd = [
            "nebula-cert", "ca",
            "-name", cfg.name,
            "-duration", cfg.ca_duration,
            "-out-key", str(tmp_key),
            "-out-crt", str(tmp_crt),
        ]
        # Explicit where the flag exists: the CA's version is inherited by
        # every certificate it signs and cannot be changed later. Where it does
        # not exist the tool predates v2 and only makes v1, which is what
        # cfg.cert_version must already say.
        if supports_cert_v2():
            cmd.extend(["-version", str(cfg.cert_version)])
        _run(cmd)
        key_age.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(tmp_key.read_bytes(), admin_keys, key_age)
        crt.write_bytes(tmp_crt.read_bytes())

    return key_age, crt


@dataclass
class SignedHost:
    """What a signing run produced for one host."""

    hostname: str
    cert_pem: bytes
    #: The public half, always.  Kept in the clear beside the certificate so a
    #: later renewal can re-sign the *same* key without decrypting anything.
    pub_pem: bytes
    #: None when the key was not generated here -- either the host keeps its
    #: own, or this was a renewal of an existing one.
    key_pem: bytes | None


def sign_host(
    ca: CaMaterial,
    cfg: NetworkConfig,
    entry: HostEntry,
    pubkey_path: Path | None = None,
) -> SignedHost:
    """Sign a certificate for ``entry``.

    Signing is always ``-in-pub``, from a public key that either already exists
    or is generated here first.  Doing it in two steps rather than letting
    ``sign -out-key`` mint the pair is what makes renewal possible: a renewal
    passes the host's existing public key and gets a fresh certificate for the
    key the host is already using, so the mesh never notices.  Letting ``sign``
    generate would silently replace the identity on every renewal.

    ``pubkey_path`` is therefore both "this host keeps its own key" and "renew
    this existing one"; ``None`` means mint a new pair.
    """
    with tempfile.TemporaryDirectory(prefix="aegis-nebula-sign-") as tmp:
        tmp_path = Path(tmp)
        out_crt = tmp_path / "host.crt"

        key_pem: bytes | None = None
        if pubkey_path is None:
            new_key = tmp_path / "host.key"
            new_pub = tmp_path / "host.pub"
            _run([
                "nebula-cert", "keygen",
                "-out-key", str(new_key),
                "-out-pub", str(new_pub),
            ])
            key_pem = new_key.read_bytes()
            pubkey_path = new_pub

        cmd = [
            "nebula-cert", "sign",
            "-ca-key", str(ca.key_path),
            "-ca-crt", str(ca.cert_path),
            "-name", entry.hostname,
            # The network prefix, not the site range: this is what tells the
            # host which addresses route over the tun device.
            #
            # -networks on Nebula 1.10+, -ip before it. The value is the same
            # single CIDR either way; v2 merely allows a list.
            _networks_flag(), f"{entry.address}/{cfg.prefix_length}",
            "-duration", cfg.cert_duration,
            "-in-pub", str(pubkey_path),
            "-out-crt", str(out_crt),
        ]
        if entry.groups:
            cmd.extend(["-groups", ",".join(entry.groups)])

        _run(cmd)

        return SignedHost(
            hostname=entry.hostname,
            cert_pem=out_crt.read_bytes(),
            pub_pem=pubkey_path.read_bytes(),
            key_pem=key_pem,
        )


# ---------------------------------------------------------------------------
# Public network description
# ---------------------------------------------------------------------------


def network_json(cfg: NetworkConfig, hosts: dict[str, HostEntry]) -> dict[str, Any]:
    """The plaintext description nixos-config evaluates.

    Deliberately public and deliberately minimal: addresses, groups and the
    lighthouses' public endpoints.  Nix cannot decrypt, so anything the module
    needs at evaluation time has to live here — and nothing that needs
    protecting is allowed to.
    """
    return {
        "network": cfg.name,
        "cidr": cfg.cidr,
        "prefixLength": cfg.prefix_length,
        "port": cfg.port,
        "hosts": {
            hostname: {
                "address": entry.address,
                "groups": entry.groups,
                "lighthouse": entry.lighthouse,
                "endpoints": entry.endpoints,
                # Not secret, and the NixOS module needs it at evaluation time
                # rather than deduced from the manifest: a host that keeps its
                # own key has to get its Nebula configuration *before* it can
                # be enrolled, or enrolling would need the very deploy it is
                # meant to avoid.
                "localKey": entry.local_key,
            }
            for hostname, entry in sorted(hosts.items())
        },
    }


def save_network_json(repo: SecretsRepo, cfg: NetworkConfig,
                      hosts: dict[str, HostEntry]) -> Path:
    path = repo.nebula_deploy_path(cfg.name) / "network.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(network_json(cfg, hosts), indent=2) + "\n")
    return path


def iter_lighthouses(hosts: dict[str, HostEntry]) -> Iterator[tuple[str, HostEntry]]:
    for hostname, entry in sorted(hosts.items()):
        if entry.lighthouse:
            yield hostname, entry
