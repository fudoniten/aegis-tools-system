"""Tests for SSH key generation."""

import pytest

from aegis import ssh


def test_generate_ssh_keypair_ed25519():
    """Generate an ed25519 keypair."""
    keypair = ssh.generate_ssh_keypair("ed25519", "test@host")
    
    assert keypair.key_type == "ed25519"
    assert keypair.comment == "test@host"
    assert keypair.public_key.startswith("ssh-ed25519")
    assert "test@host" in keypair.public_key
    assert "BEGIN OPENSSH PRIVATE KEY" in keypair.private_key


def test_generate_ssh_keypair_ecdsa():
    """Generate an ECDSA keypair."""
    keypair = ssh.generate_ssh_keypair("ecdsa", "test@host")
    
    assert keypair.key_type == "ecdsa"
    assert keypair.public_key.startswith("ecdsa-sha2")
    assert "BEGIN OPENSSH PRIVATE KEY" in keypair.private_key


def test_generate_host_keys():
    """Generate all keys for a host."""
    keys = ssh.generate_host_keys("testhost")
    
    # Check all key types generated
    assert keys.host_ed25519.public_key.startswith("ssh-ed25519")
    assert keys.host_ecdsa.public_key.startswith("ecdsa-sha2")
    assert keys.deploy_ed25519.public_key.startswith("ssh-ed25519")
    assert keys.initrd_ed25519.public_key.startswith("ssh-ed25519")
    
    # Check comments
    assert "host@testhost" in keys.host_ed25519.public_key
    assert "deploy@testhost" in keys.deploy_ed25519.public_key
    assert "initrd@testhost" in keys.initrd_ed25519.public_key


def test_host_keys_to_dict():
    """Convert host keys to dictionary."""
    keys = ssh.generate_host_keys("testhost")
    d = keys.to_dict()
    
    assert "host" in d
    assert "deploy" in d
    assert "initrd" in d
    assert "ed25519" in d["host"]
    assert "ecdsa" in d["host"]
    assert "private" in d["host"]["ed25519"]
    assert "public" in d["host"]["ed25519"]


def test_generate_sshfp_records():
    """Generate SSHFP DNS records."""
    keys = ssh.generate_host_keys("testhost")
    
    records = ssh.generate_sshfp_records(
        [keys.host_ed25519.public_key, keys.host_ecdsa.public_key],
        "testhost"
    )
    
    assert len(records) > 0
    # SSHFP records should contain the hostname
    for record in records:
        assert "testhost" in record
        assert "SSHFP" in record
