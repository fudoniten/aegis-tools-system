"""Tests for host_secrets manifest module."""

import pytest
from pathlib import Path

from aegis import host_secrets
from aegis.config import Placement


def test_secret_entry_to_dict():
    """SecretEntry converts to dict correctly."""
    entry = host_secrets.SecretEntry(
        source="test.age",
        target="/run/test",
        user="testuser",
        group="testgroup",
        mode="0600",
    )
    d = entry.to_dict()
    
    assert d["source"] == "test.age"
    assert d["target"] == "/run/test"
    assert d["user"] == "testuser"
    assert d["group"] == "testgroup"
    assert d["mode"] == "0600"


def test_secret_entry_from_dict():
    """SecretEntry parses from dict correctly."""
    data = {
        "source": "test.age",
        "target": "/run/test",
        "user": "testuser",
        "group": "testgroup",
        "mode": "0600",
        "encoding": "base64",
    }
    entry = host_secrets.SecretEntry.from_dict(data)
    
    assert entry.source == "test.age"
    assert entry.target == "/run/test"
    assert entry.user == "testuser"
    assert entry.group == "testgroup"
    assert entry.mode == "0600"
    assert entry.encoding == "base64"


def test_host_manifest_roundtrip(tmp_path: Path):
    """HostSecretsManifest saves and loads correctly."""
    manifest = host_secrets.HostSecretsManifest(hostname="testhost")
    manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entries(
        stems=["ssh_host_ed25519_key", "ssh_host_ecdsa_key"],
        placement=Placement(target_dir="/run/aegis/ssh"),
        key_types=["ed25519", "ecdsa"],
    )
    manifest.keytab = host_secrets.make_keytab_entry(
        Placement(target="/run/aegis/keytab"),
    )
    manifest.nexus_key = host_secrets.make_nexus_key_entry(
        Placement(target="/run/nexus/key", user="nexus", group="nexus"),
    )
    manifest.secrets["myservice"] = host_secrets.make_secret_entry(
        name="myservice",
        placement=Placement(
            target="/run/myservice/token", user="myservice",
            group="myservice", mode="0600"),
    )
    
    # Save
    manifest_path = host_secrets.save_host_manifest(tmp_path, manifest)
    assert manifest_path.exists()
    
    # Load
    loaded = host_secrets.load_host_manifest(tmp_path, "testhost")
    
    assert loaded.hostname == "testhost"
    assert len(loaded.ssh_host_keys) == 2
    assert loaded.ssh_host_keys[0].source == "ssh/ssh_host_ed25519_key.age"
    assert loaded.ssh_host_keys[0].target == "ssh_host_ed25519_key"
    assert loaded.ssh_host_keys[0].target_dir == "/run/aegis/ssh"
    assert loaded.ssh_host_keys[0].type == "ed25519"
    assert loaded.ssh_host_keys[1].source == "ssh/ssh_host_ecdsa_key.age"
    assert loaded.ssh_host_keys[1].type == "ecdsa"
    assert loaded.keytab is not None
    assert loaded.keytab.target == "/run/aegis/keytab"
    # No encoding: keytabs are stored as raw bytes now that crypto is binary
    # clean, so the module has nothing to decode.
    assert loaded.keytab.encoding is None
    assert loaded.nexus_key is not None
    assert loaded.nexus_key.user == "nexus"
    assert "myservice" in loaded.secrets
    assert loaded.secrets["myservice"].target == "/run/myservice/token"


def test_dnssec_manifest_roundtrip(tmp_path: Path):
    """DnssecManifest saves and loads correctly."""
    manifest = host_secrets.make_dnssec_entry(
        domain="fudo.org",
        algorithm="ECDSAP256SHA256",
        algorithm_num=13,
        keytag=12345,
        target_dir="/run/aegis/dnssec/fudo.org",
        user="nsd",
        group="nsd",
    )
    
    # Save
    manifest_path = host_secrets.save_dnssec_manifest(tmp_path, manifest)
    assert manifest_path.exists()
    
    # Load
    loaded = host_secrets.load_dnssec_manifest(tmp_path, "fudo.org")
    
    assert loaded is not None
    assert loaded.domain == "fudo.org"
    assert loaded.role == "dns-master-fudo.org"
    assert loaded.algorithm == "ECDSAP256SHA256"
    assert loaded.algorithm_num == 13
    assert loaded.keytag == 12345
    assert loaded.public_key is not None
    assert loaded.public_key.target == "/run/aegis/dnssec/fudo.org/ksk.key"
    assert loaded.public_key.mode == "0644"  # Public key is world-readable
    assert loaded.private_key is not None
    assert loaded.private_key.mode == "0400"  # Private key is protected


def test_ssh_host_key_types_field():
    """types field is set when key_types are provided."""
    entries = host_secrets.make_ssh_host_keys_entries(
        stems=["ssh_host_ed25519_key", "ssh_host_ecdsa_key"],
        key_types=["ed25519", "ecdsa"],
    )
    assert entries[0].type == "ed25519"
    assert entries[1].type == "ecdsa"

    d0 = entries[0].to_dict()
    assert d0["type"] == "ed25519"

    d1 = entries[1].to_dict()
    assert d1["type"] == "ecdsa"


def _ssh_entries(*pairs):
    return host_secrets.make_ssh_host_keys_entries(
        stems=[stem for stem, _ in pairs],
        key_types=[key_type for _, key_type in pairs],
    )


def test_merge_ssh_host_keys_keeps_other_types():
    """Importing one type at a time accumulates instead of replacing.

    The shell-loop case: `for t in ed25519 ecdsa; do aegis ssh import ...; done`
    previously left the manifest declaring only ecdsa.
    """
    existing = _ssh_entries(("ssh_host_ed25519_key", "ed25519"))
    new = _ssh_entries(("ssh_host_ecdsa_key", "ecdsa"))

    merged = host_secrets.merge_ssh_host_keys_entries(existing, new)

    assert [e.target for e in merged] == [
        "ssh_host_ed25519_key", "ssh_host_ecdsa_key"]
    assert [e.type for e in merged] == ["ed25519", "ecdsa"]


def test_merge_ssh_host_keys_replaces_same_target_in_place():
    """Re-importing a key replaces it and keeps its position."""
    existing = _ssh_entries(
        ("ssh_host_ed25519_key", "ed25519"), ("ssh_host_ecdsa_key", "ecdsa"))
    new = host_secrets.make_ssh_host_keys_entries(
        stems=["ssh_host_ed25519_key"],
        key_types=["ed25519"],
        placement=Placement(mode="0400"),
    )

    merged = host_secrets.merge_ssh_host_keys_entries(existing, new)

    assert len(merged) == 2
    assert [e.target for e in merged] == [
        "ssh_host_ed25519_key", "ssh_host_ecdsa_key"]
    assert merged[0].mode == "0400"


def test_merge_ssh_host_keys_rejects_duplicate_type():
    """Two entries of one type collapse into a single unit in the NixOS module."""
    existing = _ssh_entries(("ssh_host_ed25519_key", "ed25519"))
    new = _ssh_entries(("deploy_ed25519_key", "ed25519"))

    with pytest.raises(ValueError, match="duplicate SSH host key type"):
        host_secrets.merge_ssh_host_keys_entries(existing, new)


def test_merge_ssh_host_keys_into_empty_manifest():
    """A first import on a host with no entries is unaffected."""
    new = _ssh_entries(("ssh_host_ed25519_key", "ed25519"))
    assert host_secrets.merge_ssh_host_keys_entries([], new) == new


def test_merge_ssh_host_keys_tolerates_untyped_entries():
    """Entries without a type predate the type field; they must not collide."""
    existing = host_secrets.make_ssh_host_keys_entries(
        stems=["ssh_host_rsa_key", "ssh_host_dsa_key"])
    new = _ssh_entries(("ssh_host_ed25519_key", "ed25519"))

    merged = host_secrets.merge_ssh_host_keys_entries(existing, new)

    assert len(merged) == 3


def test_ssh_host_key_types_field_absent_without_key_types():
    """type field is absent from TOML when key_types are not provided."""
    entries = host_secrets.make_ssh_host_keys_entries(stems=["ssh_host_ed25519_key"])
    assert entries[0].type is None
    assert "type" not in entries[0].to_dict()


def test_default_values():
    """Default values are applied correctly."""
    ssh_entries = host_secrets.make_ssh_host_keys_entries(stems=["ssh_host_ed25519_key"])
    assert len(ssh_entries) == 1
    assert ssh_entries[0].source == "ssh/ssh_host_ed25519_key.age"
    assert ssh_entries[0].target == "ssh_host_ed25519_key"
    assert ssh_entries[0].target_dir == "/run/aegis/ssh"
    assert ssh_entries[0].user == "root"
    assert ssh_entries[0].group == "root"
    assert ssh_entries[0].mode == "0600"
    
    keytab_entry = host_secrets.make_keytab_entry()
    assert keytab_entry.target == "/run/aegis/keytab"
    assert keytab_entry.encoding is None
    
    nexus_entry = host_secrets.make_nexus_key_entry()
    assert nexus_entry.target == "/run/aegis/nexus-key"


def test_load_nonexistent_manifest(tmp_path: Path):
    """Loading a nonexistent manifest returns empty manifest."""
    manifest = host_secrets.load_host_manifest(tmp_path, "nonexistent")
    assert manifest.hostname == "nonexistent"
    assert manifest.ssh_host_keys == []
    assert manifest.keytab is None
    assert manifest.nexus_key is None
    assert manifest.secrets == {}


def test_load_nonexistent_dnssec_manifest(tmp_path: Path):
    """Loading a nonexistent DNSSEC manifest returns None."""
    result = host_secrets.load_dnssec_manifest(tmp_path, "nonexistent.org")
    assert result is None


def test_sequential_imports_accumulate_on_disk(tmp_path):
    """The reported regression, end to end through the manifest round-trip.

    Two `aegis ssh import` runs against the same host -- the ed25519 pass then
    the ecdsa pass -- must leave both declared. Previously the second run
    replaced the first, leaving the ed25519 ciphertext on disk with nothing in
    the manifest pointing at it.
    """
    deploy = tmp_path / "deploy"

    for stem, key_type in (("ssh_host_ed25519_key", "ed25519"),
                           ("ssh_host_ecdsa_key", "ecdsa")):
        manifest = host_secrets.load_host_manifest(deploy, "testhost")
        manifest.ssh_host_keys = host_secrets.merge_ssh_host_keys_entries(
            manifest.ssh_host_keys,
            host_secrets.make_ssh_host_keys_entries(
                stems=[stem], key_types=[key_type]),
        )
        host_secrets.save_host_manifest(deploy, manifest)

    reloaded = host_secrets.load_host_manifest(deploy, "testhost")

    assert [e.target for e in reloaded.ssh_host_keys] == [
        "ssh_host_ed25519_key", "ssh_host_ecdsa_key"]
    assert sorted(e.type for e in reloaded.ssh_host_keys) == ["ecdsa", "ed25519"]
