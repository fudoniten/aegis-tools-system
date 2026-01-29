"""Tests for host_secrets manifest module."""

import pytest
from pathlib import Path

from aegis import host_secrets


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
    manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entry(
        key_types=["ed25519", "ecdsa"],
        target_dir="/etc/ssh",
    )
    manifest.keytab = host_secrets.make_keytab_entry(
        target="/etc/krb5.keytab",
    )
    manifest.nexus_key = host_secrets.make_nexus_key_entry(
        target="/run/nexus/key",
        user="nexus",
        group="nexus",
    )
    manifest.secrets["myservice"] = host_secrets.make_secret_entry(
        name="myservice",
        target="/run/myservice/token",
        user="myservice",
        group="myservice",
        mode="0600",
    )
    
    # Save
    manifest_path = host_secrets.save_host_manifest(tmp_path, manifest)
    assert manifest_path.exists()
    
    # Load
    loaded = host_secrets.load_host_manifest(tmp_path, "testhost")
    
    assert loaded.hostname == "testhost"
    assert loaded.ssh_host_keys is not None
    assert loaded.ssh_host_keys.target_dir == "/etc/ssh"
    assert loaded.ssh_host_keys.key_types == ["ed25519", "ecdsa"]
    assert loaded.keytab is not None
    assert loaded.keytab.target == "/etc/krb5.keytab"
    assert loaded.keytab.encoding == "base64"
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
        target_dir="/var/lib/dnssec/fudo.org",
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
    assert loaded.public_key.target == "/var/lib/dnssec/fudo.org/ksk.key"
    assert loaded.public_key.mode == "0644"  # Public key is world-readable
    assert loaded.private_key is not None
    assert loaded.private_key.mode == "0400"  # Private key is protected


def test_default_values():
    """Default values are applied correctly."""
    ssh_entry = host_secrets.make_ssh_host_keys_entry(key_types=["ed25519"])
    assert ssh_entry.target_dir == "/etc/ssh"
    assert ssh_entry.user == "root"
    assert ssh_entry.group == "root"
    assert ssh_entry.mode == "0600"
    
    keytab_entry = host_secrets.make_keytab_entry()
    assert keytab_entry.target == "/etc/krb5.keytab"
    assert keytab_entry.encoding == "base64"
    
    nexus_entry = host_secrets.make_nexus_key_entry()
    assert nexus_entry.target == "/run/aegis/nexus-key"


def test_load_nonexistent_manifest(tmp_path: Path):
    """Loading a nonexistent manifest returns empty manifest."""
    manifest = host_secrets.load_host_manifest(tmp_path, "nonexistent")
    assert manifest.hostname == "nonexistent"
    assert manifest.ssh_host_keys is None
    assert manifest.keytab is None
    assert manifest.nexus_key is None
    assert manifest.secrets == {}


def test_load_nonexistent_dnssec_manifest(tmp_path: Path):
    """Loading a nonexistent DNSSEC manifest returns None."""
    result = host_secrets.load_dnssec_manifest(tmp_path, "nonexistent.org")
    assert result is None
