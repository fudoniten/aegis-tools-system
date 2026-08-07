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
    """Binary content round-trips byte-for-byte, with no wrapper."""
    keypair = crypto.generate_age_keypair()
    # Binary content with non-UTF-8 bytes (like Kerberos realm keys)
    content = b"\x00\x01\x02\xff\xfe\xfd\x80\x90\xa0binary\x00data"
    encrypted_path = tmp_path / "binary.age"

    crypto.encrypt_age(content, [keypair.public_key], encrypted_path)

    assert encrypted_path.exists()

    decrypted = crypto.decrypt_age_bytes(
        encrypted_path, identity_content=keypair.private_key)
    assert decrypted == content


def test_no_base64_sentinel_is_written(tmp_path: Path):
    """The legacy base64: wrapper is never written any more.

    It existed only because decrypt_age ran age in text mode; the NixOS module
    never stripped it, so keytabs deployed as the literal string 'base64:...'.
    """
    keypair = crypto.generate_age_keypair()
    encrypted_path = tmp_path / "binary.age"

    crypto.encrypt_age(b"\x00\xffnot text", [keypair.public_key], encrypted_path)

    raw = crypto.decrypt_age_bytes(
        encrypted_path, identity_content=keypair.private_key)
    assert not raw.startswith(b"base64:")


def test_legacy_base64_sentinel_still_reads(tmp_path: Path):
    """Material written by the old tooling stays readable without migration.

    The Kerberos realm keys and principals already in aegis-secrets carry the
    sentinel, so dropping read support would strand them.
    """
    import base64 as b64

    keypair = crypto.generate_age_keypair()
    content = b"\x00\x01\x02\xfflegacy binary"
    encrypted_path = tmp_path / "legacy.age"

    # Reproduce exactly what the old encrypt_age_binary produced
    marked = b"base64:" + b64.b64encode(content)
    crypto.encrypt_age(marked, [keypair.public_key], encrypted_path)

    decrypted = crypto.decrypt_age_bytes(
        encrypted_path, identity_content=keypair.private_key)
    assert decrypted == content


def test_recipients_are_deduplicated(tmp_path: Path):
    """A repeated recipient is collapsed, so recipient counts stay meaningful."""
    keypair = crypto.generate_age_keypair()
    encrypted_path = tmp_path / "dup.age"

    crypto.encrypt_age(
        "secret",
        [keypair.public_key, keypair.public_key, keypair.public_key],
        encrypted_path,
    )

    assert crypto.recipients_of(encrypted_path) == 1


def test_recipients_of_counts_stanzas(tmp_path: Path):
    """recipients_of reports how many keys a file was encrypted to."""
    keypairs = [crypto.generate_age_keypair() for _ in range(3)]
    encrypted_path = tmp_path / "multi.age"

    crypto.encrypt_age(
        "secret", [k.public_key for k in keypairs], encrypted_path)

    assert crypto.recipients_of(encrypted_path) == 3


# generate_secret ----------------------------------------------------------
#
# Defaults listed in the docstring of generate_secret; tests below pin each
# one.  These run in milliseconds because secrets.token_bytes is fast.


def test_generate_secret_hex_default_length():
    """Default length 32 hex chars = 128 bits."""
    out = crypto.generate_secret()
    assert len(out) == 32
    assert out == out.lower()
    int(out, 16)  # raises if not valid hex


def test_generate_secret_hex_with_length():
    """Hex output respects caller-supplied char length."""
    out = crypto.generate_secret(format="hex", length=64)
    assert len(out) == 64
    int(out, 16)


def test_generate_secret_base64():
    """Base64 output is unpadded standard alphabet."""
    out = crypto.generate_secret(format="base64", length=16)
    # 16 random bytes -> 22 base64 chars with padding, 22 unpadded (we strip)
    assert len(out) == 22
    assert b"=" not in out
    for c in out:
        assert c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def test_generate_secret_base64url():
    """base64url uses URL-safe alphabet."""
    out = crypto.generate_secret(format="base64url", length=16)
    for c in out:
        assert c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert b"=" not in out


def test_generate_secret_alphanumeric_default_charset():
    """alphanumeric without --charset draws from the 62-char default."""
    out = crypto.generate_secret(format="alphanumeric", length=64)
    for c in out.decode("ascii"):
        assert c in crypto.DEFAULT_ALPHANUMERIC


def test_generate_secret_alphanumeric_explicit_charset():
    """alphanumeric with a custom charset restricts to that alphabet."""
    out = crypto.generate_secret(
        format="alphanumeric", length=32, charset="abc"
    )
    for c in out.decode("ascii"):
        assert c in "abc"


def test_generate_secret_alphabet_presets_resolve():
    """Named presets match the documented alphabets."""
    for name, alphabet in crypto.ALPHABET_PRESETS.items():
        out = crypto.generate_secret(
            format="alphanumeric", length=20, charset=name
        )
        for c in out.decode("ascii"):
            assert c in alphabet, f"{name} produced {c!r} outside its alphabet"


def test_generate_secret_raw_byte_count():
    """raw output is exactly `length` bytes."""
    out = crypto.generate_secret(format="raw", length=24)
    assert isinstance(out, bytes)
    assert len(out) == 24


def test_generate_secret_rejects_zero_length():
    with pytest.raises(ValueError):
        crypto.generate_secret(length=0)


def test_generate_secret_rejects_empty_charset():
    with pytest.raises(ValueError):
        crypto.generate_secret(format="alphanumeric", length=8, charset="")


def test_generate_secret_rejects_unknown_format():
    with pytest.raises(ValueError):
        crypto.generate_secret(format="rot13", length=8)


def test_generate_secret_outputs_differ_across_calls():
    """Two consecutive invocations produce unrelated output."""
    a = crypto.generate_secret(length=32)
    b = crypto.generate_secret(length=32)
    assert a != b

