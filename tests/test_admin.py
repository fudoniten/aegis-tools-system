"""Tests for the admin recipient set."""

import pytest
from pathlib import Path

from aegis import admin, config, crypto
from aegis.errors import AdminKeyError


def test_recipients_from_directory(repo: config.SecretsRepo, admin_key):
    """The admin set is read from keys/admin/*.pub."""
    assert admin.recipients(repo) == [admin_key.public_key]


def test_multiple_recipients(repo: config.SecretsRepo, admin_key):
    """Several admin keys can be registered, and all are returned."""
    backup = crypto.generate_age_keypair()
    admin.add_key(repo, backup.public_key, "backup")

    keys = admin.recipients(repo)
    assert set(keys) == {admin_key.public_key, backup.public_key}


def test_legacy_single_file_still_read(tmp_path: Path, admin_key):
    """A repo with the historical keys/admin.pub keeps working."""
    repo = config.SecretsRepo(tmp_path)
    (tmp_path / "keys").mkdir(parents=True)
    repo.legacy_admin_key_path().write_text(admin_key.public_key + "\n")

    assert admin.recipients(repo) == [admin_key.public_key]


def test_directory_wins_over_legacy(tmp_path: Path, admin_key):
    """Once keys/admin/ has entries, the loose file is ignored."""
    repo = config.SecretsRepo(tmp_path)
    repo.ensure_structure()

    stale = crypto.generate_age_keypair()
    repo.legacy_admin_key_path().write_text(stale.public_key + "\n")
    admin.add_key(repo, admin_key.public_key, "primary")

    assert admin.recipients(repo) == [admin_key.public_key]


def test_migrate_legacy(tmp_path: Path, admin_key):
    """Migration moves keys/admin.pub into the directory form."""
    repo = config.SecretsRepo(tmp_path)
    (tmp_path / "keys").mkdir(parents=True)
    repo.legacy_admin_key_path().write_text(admin_key.public_key + "\n")

    out = admin.migrate_legacy(repo)

    assert out is not None and out.name == "primary.pub"
    assert not repo.legacy_admin_key_path().exists()
    assert admin.recipients(repo) == [admin_key.public_key]


def test_no_admin_keys_is_an_error(tmp_path: Path, admin_key):
    """A repo with no declared admin keys fails loudly rather than guessing."""
    repo = config.SecretsRepo(tmp_path)
    repo.ensure_structure()

    with pytest.raises(AdminKeyError, match="No admin public keys"):
        admin.recipients(repo)


def test_validate_rejects_unregistered_local_key(repo: config.SecretsRepo):
    """Using an unregistered admin key is caught before anything is written.

    Otherwise the operator produces files no other admin can read, and only
    finds out much later when someone tries to decrypt.
    """
    other = crypto.generate_age_keypair()
    # Replace the registered key with somebody else's
    for path in repo.admin_keys_path().glob("*.pub"):
        path.unlink()
    admin.add_key(repo, other.public_key, "someone-else")

    with pytest.raises(AdminKeyError, match="not registered"):
        admin.validate_local_key(repo)


def test_add_key_rejects_non_age_key(repo: config.SecretsRepo):
    with pytest.raises(AdminKeyError, match="age public key"):
        admin.add_key(repo, "ssh-ed25519 AAAAC3Nza", "bogus")


def test_comments_and_blanks_ignored(repo: config.SecretsRepo, admin_key):
    """Key files may carry comments."""
    path = repo.admin_keys_path() / "commented.pub"
    other = crypto.generate_age_keypair()
    path.write_text(f"# created 2026-01-01 by niten\n\n{other.public_key}\n")

    assert other.public_key in admin.recipients(repo)


def test_secrets_are_encrypted_for_every_admin(
    repo: config.SecretsRepo, admin_key, tmp_path: Path
):
    """All registered admins can decrypt, which is the point of the set."""
    backup = crypto.generate_age_keypair()
    admin.add_key(repo, backup.public_key, "backup")

    out = tmp_path / "secret.age"
    crypto.encrypt_age("recoverable", admin.recipients(repo), out)

    assert crypto.decrypt_age(out, identity_content=admin_key.private_key) == "recoverable"
    assert crypto.decrypt_age(out, identity_content=backup.private_key) == "recoverable"


def test_admin_key_path_env_override(tmp_path: Path, monkeypatch):
    """AEGIS_ADMIN_KEY lets the admin key live somewhere other than ~/.config."""
    elsewhere = tmp_path / "offline" / "key.txt"
    elsewhere.parent.mkdir(parents=True)
    keypair = crypto.generate_age_keypair()
    elsewhere.write_text(keypair.private_key + "\n")

    monkeypatch.setenv("AEGIS_ADMIN_KEY", str(elsewhere))

    assert crypto.default_admin_key_path() == elsewhere
    assert crypto.get_admin_public_key() == keypair.public_key


def test_admin_key_path_default_without_override(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("AEGIS_ADMIN_KEY", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    assert crypto.default_admin_key_path() == tmp_path / ".config" / "aegis" / "key.txt"
