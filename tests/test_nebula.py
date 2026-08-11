"""Tests for the Nebula overlay generator."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis import crypto, host_secrets, nebula
from aegis.config import Placement

from .conftest import add_host, requires

needs_nebula = requires("nebula-cert")
needs_age = requires("age")


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------


def test_address_allocation_prefers_the_site_range():
    cfg = nebula.NetworkConfig(
        name="fudo",
        cidr="10.200.0.0/16",
        site_ranges={"seattle": "10.200.10.0/24"},
    )
    assert nebula.allocate_address(cfg, taken=set(), site="seattle") == "10.200.10.1"


def test_address_allocation_skips_taken_addresses():
    cfg = nebula.NetworkConfig(
        name="fudo",
        cidr="10.200.0.0/16",
        site_ranges={"seattle": "10.200.10.0/24"},
    )
    taken = {"10.200.10.1", "10.200.10.2"}
    assert nebula.allocate_address(cfg, taken, site="seattle") == "10.200.10.3"


def test_address_allocation_falls_back_to_the_network():
    """An unknown site must not fail allocation, just lose the tidy grouping."""
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    assert nebula.allocate_address(cfg, taken=set(), site="nowhere") == "10.200.0.1"


def test_duplicate_addresses_are_rejected():
    hosts = {
        "a": nebula.HostEntry(hostname="a", address="10.200.0.1"),
        "b": nebula.HostEntry(hostname="b", address="10.200.0.1"),
    }
    with pytest.raises(nebula.NebulaError, match="both assigned"):
        nebula.assert_unique(hosts)


def test_network_config_round_trip(repo):
    cfg = nebula.NetworkConfig(
        name="fudo",
        cidr="10.200.0.0/16",
        port=4242,
        cert_version=1,
        site_ranges={"seattle": "10.200.10.0/24"},
    )
    nebula.save_network(repo, cfg)
    loaded = nebula.load_network(repo, "fudo")

    assert loaded.cidr == "10.200.0.0/16"
    assert loaded.cert_version == 1
    assert loaded.site_ranges == {"seattle": "10.200.10.0/24"}
    assert loaded.prefix_length == 16


def test_host_entry_round_trip(repo):
    nebula.save_network(repo, nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16"))
    entry = nebula.HostEntry(
        hostname="laptop",
        address="10.200.90.1",
        groups=["site-mobile", "laptop"],
        local_key=True,
    )
    nebula.save_host(repo, "fudo", entry)
    loaded = nebula.load_host(repo, "fudo", "laptop")

    assert loaded.address == "10.200.90.1"
    assert loaded.groups == ["site-mobile", "laptop"]
    assert loaded.local_key is True
    assert loaded.lighthouse is False


def test_network_json_is_public_only():
    """network.json is read by Nix at evaluation time and cannot be decrypted,
    so nothing needing protection may appear in it."""
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    hosts = {
        "procul": nebula.HostEntry(
            hostname="procul",
            address="10.200.24.1",
            lighthouse=True,
            endpoints=["203.0.113.9:4242"],
        ),
        "laptop": nebula.HostEntry(
            hostname="laptop", address="10.200.90.1", local_key=True
        ),
    }
    doc = nebula.network_json(cfg, hosts)

    assert doc["prefixLength"] == 16
    assert doc["hosts"]["procul"]["lighthouse"] is True
    assert doc["hosts"]["procul"]["endpoints"] == ["203.0.113.9:4242"]
    # The NixOS module needs custody at evaluation time; see cli_nebula.
    assert doc["hosts"]["laptop"]["localKey"] is True

    flat = repr(doc)
    for forbidden in ("PRIVATE KEY", "age1", "BEGIN NEBULA"):
        assert forbidden not in flat


# ---------------------------------------------------------------------------
# Manifest entries
# ---------------------------------------------------------------------------


def test_manifest_entries_are_owned_by_the_service_user():
    """The upstream NixOS module runs Nebula as nebula-<network>, so a key it
    cannot read is a key it cannot use."""
    entries = host_secrets.make_nebula_entries("fudo", with_key=True)

    assert set(entries) == {
        "nebula-fudo-key",
        "nebula-fudo-cert",
        "nebula-fudo-ca",
    }
    key = entries["nebula-fudo-key"]
    assert key.user == "nebula-fudo"
    assert key.group == "nebula-fudo"
    assert key.mode == "0400"
    assert key.target == "/run/aegis/nebula/fudo.key"


def test_manifest_omits_the_key_for_a_host_that_keeps_its_own():
    entries = host_secrets.make_nebula_entries("fudo", with_key=False)
    assert "nebula-fudo-key" not in entries
    assert "nebula-fudo-cert" in entries


def test_manifest_placement_can_be_overridden():
    entries = host_secrets.make_nebula_entries(
        "fudo", with_key=True, placement=Placement(target_dir="/run/nebula", user="root")
    )
    assert entries["nebula-fudo-key"].target == "/run/nebula/fudo.key"
    assert entries["nebula-fudo-key"].user == "root"


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------


@needs_nebula
def test_capabilities_are_probed_not_assumed():
    """The nebula-cert CLI changed in 1.10: `sign -ip` became `-networks`, and
    `ca` gained `-version`. Whichever this machine has, the probe must agree
    with itself -- a tool that offers -version is one that offers -networks."""
    nebula._cert_capabilities.cache_clear()
    caps = nebula._cert_capabilities()

    assert nebula.supports_cert_v2() == ("ca:version" in caps)
    assert nebula.default_cert_version() == (2 if nebula.supports_cert_v2() else 1)
    expected = "-networks" if nebula.supports_cert_v2() else "-ip"
    assert nebula._networks_flag() == expected


@needs_nebula
@needs_age
def test_v2_is_refused_when_the_tool_cannot_make_it(repo, admin_key, monkeypatch):
    """Asking for a format the tool cannot produce must fail with an
    explanation, not a bare 'flag provided but not defined'."""
    monkeypatch.setattr(nebula, "supports_cert_v2", lambda: False)
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16", cert_version=2)

    with pytest.raises(nebula.NebulaError, match="version 2 certificates"):
        nebula.create_ca(repo, cfg, [admin_key.public_key])


@needs_nebula
@needs_age
def test_cert_details_accepts_both_json_shapes(repo, admin_key, monkeypatch):
    """`print -json` emits a bare object up to 1.9 and an array from 1.10."""
    import json as _json

    cfg = nebula.NetworkConfig(
        name="fudo",
        cidr="10.200.0.0/16",
        cert_version=nebula.default_cert_version(),
    )
    _, ca_cert = nebula.create_ca(repo, cfg, [admin_key.public_key])

    # Whatever shape this nebula-cert produced, both must parse.
    details = nebula.cert_details(ca_cert)

    monkeypatch.setattr(nebula, "_run", lambda cmd: _json.dumps([details]))
    assert nebula.cert_details(ca_cert)["details"]["isCa"] is True

    monkeypatch.setattr(nebula, "_run", lambda cmd: _json.dumps(details))
    assert nebula.cert_details(ca_cert)["details"]["isCa"] is True


@needs_nebula
@needs_age
def test_ca_key_is_never_stored_in_the_clear(repo, admin_key):
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    key_path, cert_path = nebula.create_ca(repo, cfg, [admin_key.public_key])

    assert key_path.read_text().startswith("-----BEGIN AGE ENCRYPTED FILE-----")
    assert "NEBULA" in cert_path.read_text()
    # The certificate is public and deliberately readable.
    assert nebula.cert_details(cert_path)["details"]["isCa"] is True


@needs_nebula
@needs_age
def test_ca_refuses_to_overwrite_itself(repo, admin_key):
    """Replacing a CA orphans every certificate it ever signed."""
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    nebula.create_ca(repo, cfg, [admin_key.public_key])

    with pytest.raises(nebula.NebulaError, match="already has a CA"):
        nebula.create_ca(repo, cfg, [admin_key.public_key])


@needs_nebula
@needs_age
def test_signing_uses_the_network_prefix_not_the_site_range(repo, admin_key):
    """A site prefix would leave every other site unreachable over the tun."""
    cfg = nebula.NetworkConfig(
        name="fudo",
        cidr="10.200.0.0/16",
        site_ranges={"seattle": "10.200.10.0/24"},
    )
    nebula.create_ca(repo, cfg, [admin_key.public_key])
    entry = nebula.HostEntry(
        hostname="nostromo", address="10.200.10.1", groups=["server"]
    )

    with nebula.CaMaterial(repo, "fudo") as ca:
        signed = nebula.sign_host(ca, cfg, entry)

    tmp = repo.path / "out.crt"
    tmp.write_bytes(signed.cert_pem)
    details = nebula.cert_details(tmp)["details"]

    # v1 calls the field "ips" and v2 "networks"; the value is the same single
    # CIDR either way, and the /16 is the point of the test.
    addresses = details.get("networks") or details.get("ips")
    assert addresses == ["10.200.10.1/16"]
    assert details["name"] == "nostromo"
    assert details["groups"] == ["server"]
    assert signed.key_pem is not None
    assert signed.pub_pem


@needs_nebula
@needs_age
def test_renewal_preserves_the_host_key(repo, admin_key):
    """Signing must be able to re-issue against an existing public key.  If a
    renewal minted a new pair the host would silently drop off the mesh."""
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    nebula.create_ca(repo, cfg, [admin_key.public_key])
    entry = nebula.HostEntry(hostname="nostromo", address="10.200.10.1")

    with nebula.CaMaterial(repo, "fudo") as ca:
        first = nebula.sign_host(ca, cfg, entry)

        pub = repo.path / "host.pub"
        pub.write_bytes(first.pub_pem)
        second = nebula.sign_host(ca, cfg, entry, pubkey_path=pub)

    assert second.key_pem is None, "a renewal must not mint key material"
    assert second.pub_pem == first.pub_pem


@needs_nebula
@needs_age
def test_expiry_is_parsed_and_renewal_window_respected(repo, admin_key):
    cfg = nebula.NetworkConfig(
        name="fudo", cidr="10.200.0.0/16", cert_duration="24h"
    )
    nebula.create_ca(repo, cfg, [admin_key.public_key])
    entry = nebula.HostEntry(hostname="nostromo", address="10.200.10.1")

    with nebula.CaMaterial(repo, "fudo") as ca:
        signed = nebula.sign_host(ca, cfg, entry)

    cert = repo.path / "out.crt"
    cert.write_bytes(signed.cert_pem)

    expiry = nebula.cert_expiry(cert)
    assert expiry > datetime.now(timezone.utc)
    assert expiry - datetime.now(timezone.utc) < timedelta(days=2)

    assert nebula.needs_renewal(cert, within_days=30) is True
    assert nebula.needs_renewal(cert, within_days=0) is False


@needs_nebula
@needs_age
def test_ca_material_removes_the_decrypted_key(repo, admin_key):
    """The CA private key exists in the clear only inside the context."""
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    nebula.create_ca(repo, cfg, [admin_key.public_key])

    with nebula.CaMaterial(repo, "fudo") as ca:
        key_path = ca.key_path
        assert key_path.exists()

    assert not key_path.exists()


@needs_nebula
@needs_age
def test_fingerprint_is_reported_for_the_blocklist(repo, admin_key):
    cfg = nebula.NetworkConfig(name="fudo", cidr="10.200.0.0/16")
    nebula.create_ca(repo, cfg, [admin_key.public_key])
    entry = nebula.HostEntry(hostname="laptop", address="10.200.90.1")

    with nebula.CaMaterial(repo, "fudo") as ca:
        signed = nebula.sign_host(ca, cfg, entry)

    cert = repo.path / "out.crt"
    cert.write_bytes(signed.cert_pem)

    fingerprint = nebula.cert_fingerprint(cert)
    assert len(fingerprint) == 64
    assert all(c in "0123456789abcdef" for c in fingerprint)
