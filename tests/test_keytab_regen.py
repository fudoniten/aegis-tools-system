"""'aegis build keytabs' always re-extracts; it should only ever *rewrite*
keytab.age when the plaintext actually changed.

A keytab is a build artifact, not secret material of its own: the principal
keys inside it are what's immutable, extracting them into a keytab is just
packaging. Building a keytab needs a live Heimdal database, so the KDC-facing
calls (instantiate_realm, extract_host_keytab) are stubbed here -- what these
tests pin down is the decrypt-compare-then-write decision around them, using
real age encryption throughout, which is exactly the part that changed.
"""

from pathlib import Path

from typer.testing import CliRunner

from aegis import config, crypto, realm as realm_mod
from aegis.cli import app

from .conftest import add_host

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _setup_realm_member(repo: config.SecretsRepo, admin_key, hostname="rama",
                         realm="A.ORG", domain="a.org", services=None):
    """A single host, real enough to reach build_keytabs' extraction step:
    registered, in the realm's domain role, with 'host'/'ssh' principals
    already stored (so add_host_to_realm -- also Heimdal-backed -- is never
    reached) and a real encrypted realm key."""
    services = services or ["host", "ssh"]
    keypair = add_host(repo, hostname, services=services)

    repo.set_role_config(config.RoleConfig(
        name=f"domain-{domain}", hosts=[hostname]))

    repo.realm_principals_path(realm).mkdir(parents=True, exist_ok=True)
    realm_mod.save(repo, realm_mod.RealmConfig(name=realm, domains=[domain]))

    admin_keys = [admin_key.public_key]
    crypto.encrypt_age(b"fake-realm-key", admin_keys, repo.realm_key_path(realm))

    fqdn = f"{hostname}.{domain}"
    for svc in services:
        crypto.encrypt_age(
            f"fake-{svc}-principal-key".encode(), admin_keys,
            repo.realm_principals_path(realm) / f"{svc}_{fqdn}.age")

    return keypair, fqdn


def _stub_kdc(monkeypatch, keytab_bytes: bytes):
    """Stand in for the two calls that need a live Heimdal database.
    add_host_to_realm is intentionally left unstubbed: _setup_realm_member
    already stores every service's principal, so build_keytabs never finds
    one 'missing' and never calls it."""
    import aegis.kerberos as krb

    def fake_instantiate_realm(realm, realm_data_path, etypes=None, verbose=False):
        return Path("/fake/kdc.conf")

    def fake_extract_host_keytab(hostname, kdc_conf_path, output_path,
                                  services=None, all_keys=False, verbose=False):
        output_path.write_bytes(keytab_bytes)
        return output_path

    monkeypatch.setattr(krb, "instantiate_realm", fake_instantiate_realm)
    monkeypatch.setattr(krb, "extract_host_keytab", fake_extract_host_keytab)


def _build(repo: config.SecretsRepo, realm="A.ORG"):
    result = runner.invoke(app, [
        "build", "keytabs", "--realm", realm, "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)
    return result


def test_first_build_writes_keytab(repo: config.SecretsRepo, admin_key, monkeypatch):
    keypair, _ = _setup_realm_member(repo, admin_key)
    _stub_kdc(monkeypatch, b"keytab-v1")

    result = _build(repo)

    keytab_path = repo.host_deploy_path("rama") / "keytab.age"
    assert keytab_path.exists()
    assert "Wrote:" in _out(result)
    assert crypto.decrypt_age_bytes(
        keytab_path, identity_content=keypair.private_key) == b"keytab-v1"


def test_unchanged_content_does_not_rewrite_ciphertext(
    repo: config.SecretsRepo, admin_key, monkeypatch
):
    """Re-running with the same underlying principals must not touch the
    file on disk -- age is randomized, so a real re-encryption of identical
    plaintext would still produce different ciphertext bytes. Comparing the
    raw bytes before and after is therefore a faithful check that the
    'unchanged' path skipped the write, not just that it produced an
    equivalent result."""
    keypair, _ = _setup_realm_member(repo, admin_key)
    _stub_kdc(monkeypatch, b"keytab-v1")
    _build(repo)

    keytab_path = repo.host_deploy_path("rama") / "keytab.age"
    before = keytab_path.read_bytes()

    result = _build(repo)

    after = keytab_path.read_bytes()
    assert before == after, "keytab.age was rewritten despite unchanged content"
    assert "Keytab unchanged" in _out(result)
    assert "Wrote:" not in _out(result)


def test_changed_content_rewrites_keytab(
    repo: config.SecretsRepo, admin_key, monkeypatch
):
    """The case this whole change exists for: a service was added to a host
    that already has a keytab (nfs, say), so the newly-extracted plaintext
    differs -- the file must be rewritten to reflect it."""
    keypair, _ = _setup_realm_member(repo, admin_key)
    _stub_kdc(monkeypatch, b"keytab-v1")
    _build(repo)

    keytab_path = repo.host_deploy_path("rama") / "keytab.age"
    before = keytab_path.read_bytes()

    _stub_kdc(monkeypatch, b"keytab-v2-with-nfs")
    result = _build(repo)

    after = keytab_path.read_bytes()
    assert before != after
    assert "Wrote:" in _out(result)
    assert crypto.decrypt_age_bytes(
        keytab_path, identity_content=keypair.private_key
    ) == b"keytab-v2-with-nfs"


def test_undecryptable_existing_keytab_is_replaced_not_fatal(
    repo: config.SecretsRepo, admin_key, monkeypatch
):
    """A keytab.age this admin key can't read (rotated away, corrupted) must
    not abort the build -- it should be treated as 'differs' and replaced,
    with a warning rather than a crash."""
    keypair, fqdn = _setup_realm_member(repo, admin_key)

    keytab_path = repo.host_deploy_path("rama") / "keytab.age"
    keytab_path.parent.mkdir(parents=True, exist_ok=True)
    keytab_path.write_bytes(b"not a valid age file")

    _stub_kdc(monkeypatch, b"keytab-v1")
    result = _build(repo)

    assert "couldn't decrypt existing keytab" in _out(result)
    assert crypto.decrypt_age_bytes(
        keytab_path, identity_content=keypair.private_key
    ) == b"keytab-v1"


def test_force_flag_still_accepted(repo: config.SecretsRepo, admin_key, monkeypatch):
    """--force is now a no-op, kept only so existing callers/docs don't break."""
    _setup_realm_member(repo, admin_key)
    _stub_kdc(monkeypatch, b"keytab-v1")

    result = runner.invoke(app, [
        "build", "keytabs", "--realm", "A.ORG", "--force",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 0, _out(result)
