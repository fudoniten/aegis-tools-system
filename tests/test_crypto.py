"""Tests for crypto module."""

import pytest
from pathlib import Path

from aegis import crypto


def test_generate_age_keypair():
    """Generate a valid age keypair."""
    keypair = crypto.generate_age_keypair()
    
    assert keypair.public_key.startswith("age1")
    assert "AGE-SECRET-KEY" in keypair.private_key


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    """Encrypt then decrypt returns original content."""
    keypair = crypto.generate_age_keypair()
    content = "secret data for testing"
    encrypted_path = tmp_path / "secret.age"
    
    crypto.encrypt_age(content, [keypair.public_key], encrypted_path)
    
    assert encrypted_path.exists()
    assert encrypted_path.read_text().startswith("-----BEGIN AGE ENCRYPTED FILE-----")
    
    decrypted = crypto.decrypt_age(encrypted_path, identity_content=keypair.private_key)
    
    assert decrypted == content


def test_multi_recipient(tmp_path: Path):
    """Multiple recipients can each decrypt."""
    keypair1 = crypto.generate_age_keypair()
    keypair2 = crypto.generate_age_keypair()
    content = "shared secret"
    encrypted_path = tmp_path / "shared.age"
    
    crypto.encrypt_age(content, [keypair1.public_key, keypair2.public_key], encrypted_path)
    
    # Both should be able to decrypt
    assert crypto.decrypt_age(encrypted_path, identity_content=keypair1.private_key) == content
    assert crypto.decrypt_age(encrypted_path, identity_content=keypair2.private_key) == content


def test_encrypt_requires_recipient(tmp_path: Path):
    """Encryption fails without recipients."""
    with pytest.raises(ValueError, match="[Aa]t least one recipient"):
        crypto.encrypt_age("secret", [], tmp_path / "empty.age")


def test_can_decrypt_check(tmp_path: Path):
    """can_decrypt returns correct boolean."""
    keypair1 = crypto.generate_age_keypair()
    keypair2 = crypto.generate_age_keypair()
    encrypted_path = tmp_path / "test.age"
    identity_path = tmp_path / "key.txt"
    wrong_identity_path = tmp_path / "wrong.txt"
    
    # Encrypt for keypair1 only
    crypto.encrypt_age("secret", [keypair1.public_key], encrypted_path)
    
    # Write identity files
    identity_path.write_text(keypair1.private_key)
    wrong_identity_path.write_text(keypair2.private_key)
    
    assert crypto.can_decrypt(encrypted_path, identity_path) is True
    assert crypto.can_decrypt(encrypted_path, wrong_identity_path) is False


def test_binary_encrypt_decrypt_roundtrip(tmp_path: Path):
    """Encrypt then decrypt binary content returns original bytes."""
    keypair = crypto.generate_age_keypair()
    # Binary content with non-UTF-8 bytes (like Kerberos keys)
    content = b"\x00\x01\x02\xff\xfe\xfd\x80\x90\xa0binary\x00data"
    encrypted_path = tmp_path / "binary.age"
    
    crypto.encrypt_age_binary(content, [keypair.public_key], encrypted_path)
    
    assert encrypted_path.exists()
    # The encrypted content should contain the base64 marker when decrypted as text
    decrypted_text = crypto.decrypt_age(encrypted_path, identity_content=keypair.private_key)
    assert decrypted_text.startswith("base64:")
    
    # Binary decrypt should return original bytes
    decrypted = crypto.decrypt_age_binary(encrypted_path, identity_content=keypair.private_key)
    
    assert decrypted == content


def test_binary_decrypt_fallback_for_text(tmp_path: Path):
    """decrypt_age_binary falls back to encoding text if no base64 marker."""
    keypair = crypto.generate_age_keypair()
    content = "plain text content"
    encrypted_path = tmp_path / "text.age"
    
    # Encrypt as text (no base64 marker)
    crypto.encrypt_age(content, [keypair.public_key], encrypted_path)
    
    # Binary decrypt should still work, returning encoded bytes
    decrypted = crypto.decrypt_age_binary(encrypted_path, identity_content=keypair.private_key)
    
    assert decrypted == content.encode("utf-8")
