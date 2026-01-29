"""Tests for DNSSEC module."""

import pytest
from pathlib import Path

from aegis import dnssec


def test_parse_dnssec_filename_valid():
    """Parse a valid DNSSEC filename."""
    result = dnssec.parse_dnssec_filename("Kfudo.org.+013+11926.key")
    assert result == ("fudo.org", 13, 11926)


def test_parse_dnssec_filename_with_subdomain():
    """Parse a DNSSEC filename with subdomain."""
    result = dnssec.parse_dnssec_filename("Ksea.fudo.org.+015+54321.private")
    assert result == ("sea.fudo.org", 15, 54321)


def test_parse_dnssec_filename_ds():
    """Parse a DS record filename."""
    result = dnssec.parse_dnssec_filename("Kexample.com.+008+12345.ds")
    assert result == ("example.com", 8, 12345)


def test_parse_dnssec_filename_invalid():
    """Invalid filenames return None."""
    assert dnssec.parse_dnssec_filename("not-a-key.txt") is None
    assert dnssec.parse_dnssec_filename("Kfudo.org.key") is None  # Missing algorithm/keytag
    assert dnssec.parse_dnssec_filename("Kfudo.org.+13+11926.key") is None  # Algorithm not 3 digits


def test_algorithm_map():
    """Check algorithm mappings."""
    assert dnssec.ALGORITHM_MAP["ECDSAP256SHA256"] == 13
    assert dnssec.ALGORITHM_MAP["ED25519"] == 15
    assert dnssec.ALGORITHM_NAMES[13] == "ECDSAP256SHA256"


def test_find_dnssec_keys(tmp_path: Path):
    """Find DNSSEC key files in a directory."""
    domain = "test.example.com"
    
    # Create fake key files
    (tmp_path / "Ktest.example.com.+013+12345.key").write_text("public key")
    (tmp_path / "Ktest.example.com.+013+12345.private").write_text("private key")
    (tmp_path / "Ktest.example.com.+013+12345.ds").write_text("DS record")
    
    result = dnssec.find_dnssec_keys(tmp_path, domain)
    
    assert result is not None
    assert result.domain == domain
    assert result.algorithm == "ECDSAP256SHA256"
    assert result.algorithm_num == 13
    assert result.keytag == 12345
    assert result.key_file.exists()
    assert result.private_file.exists()
    assert result.ds_file.exists()


def test_find_dnssec_keys_not_found(tmp_path: Path):
    """Return None when no keys found."""
    result = dnssec.find_dnssec_keys(tmp_path, "nonexistent.org")
    assert result is None


def test_find_dnssec_keys_missing_private(tmp_path: Path):
    """Return None when private key is missing."""
    domain = "test.example.com"
    
    # Only create the public key
    (tmp_path / "Ktest.example.com.+013+12345.key").write_text("public key")
    
    result = dnssec.find_dnssec_keys(tmp_path, domain)
    assert result is None


def test_dnssec_key_files_basename():
    """Test DnssecKeyFiles.basename property."""
    key_files = dnssec.DnssecKeyFiles(
        domain="fudo.org",
        algorithm="ECDSAP256SHA256",
        algorithm_num=13,
        keytag=11926,
        key_file=Path("/tmp/Kfudo.org.+013+11926.key"),
        private_file=Path("/tmp/Kfudo.org.+013+11926.private"),
        ds_file=Path("/tmp/Kfudo.org.+013+11926.ds"),
    )
    
    assert key_files.basename == "Kfudo.org.+013+11926"
