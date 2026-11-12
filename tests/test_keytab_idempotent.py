"""'aegis build keytabs' must leave every unchanged output alone.

Heimdal's ext_keytab stamps each entry with the time it was extracted, so an
unchanged principal set still yields a keytab whose bytes differ from the last
build's. Comparing raw plaintext therefore rewrote every host keytab, every
KDC daemon keytab, and every named keytab copy on every build, dirtying git
each time. These pin down that the comparison ignores those timestamps but
nothing else, and that the KDC bundle and realm key are compared too.
"""

import shutil
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis import config, crypto, kerberos as krb, realm as realm_mod
from aegis.cli import app

from .conftest import add_host, requires

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _counted(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def _entry(principal: str, realm: str, *, timestamp: int, kvno: int = 1,
           enctype: int = 18, key: bytes = b"k" * 32) -> bytes:
    components = principal.split("/")
    body = (struct.pack(">H", len(components)) + _counted(realm.encode())
            + b"".join(_counted(c.encode()) for c in components)
            + struct.pack(">I", 1)                 # name_type
            + struct.pack(">I", timestamp)
            + struct.pack(">B", kvno % 256)
            + struct.pack(">H", enctype) + _counted(key)
            + struct.pack(">I", kvno))             # 32-bit kvno
    return struct.pack(">i", len(body)) + body


def _keytab(*entries: bytes) -> bytes:
    return b"\x05\x02" + b"".join(entries)


# The comparison ---------------------------------------------------------------

def test_timestamps_alone_do_not_make_keytabs_differ():
    a = _keytab(_entry("host/a.a.org", "A.ORG", timestamp=1000),
                _entry("ssh/a.a.org", "A.ORG", timestamp=1000))
    b = _keytab(_entry("host/a.a.org", "A.ORG", timestamp=2000),
                _entry("ssh/a.a.org", "A.ORG", timestamp=2001))
    assert a != b
    assert krb.keytabs_equivalent(a, b)


@pytest.mark.parametrize("change", [
    {"key": b"x" * 32},
    {"kvno": 2},
    {"enctype": 17},
])
def test_anything_else_does(change):
    a = _keytab(_entry("host/a.a.org", "A.ORG", timestamp=1000))
    b = _keytab(_entry("host/a.a.org", "A.ORG", timestamp=1000, **change))
    assert not krb.keytabs_equivalent(a, b)


def test_an_added_entry_differs():
    one = _entry("host/a.a.org", "A.ORG", timestamp=1000)
    assert not krb.keytabs_equivalent(
        _keytab(one), _keytab(one, _entry("nfs/a.a.org", "A.ORG", timestamp=1000)))


def test_holes_are_ignored():
    entry = _entry("host/a.a.org", "A.ORG", timestamp=1000)
    hole = struct.pack(">i", -8) + b"\x00" * 8
    assert krb.keytabs_equivalent(_keytab(entry), _keytab(hole, entry))


def test_non_keytab_bytes_fall_back_to_exact_comparison():
    assert krb.keytab_entries(b"not a keytab") is None
    assert krb.keytabs_equivalent(b"same", b"same")
    assert not krb.keytabs_equivalent(b"same", b"diff")
    # Truncated: unparseable, so not equivalent to the whole one.
    whole = _keytab(_entry("host/a.a.org", "A.ORG", timestamp=1))
    assert not krb.keytabs_equivalent(whole, whole[:-3])


# The build --------------------------------------------------------------------

REALM, DOMAIN, HOST = "A.ORG", "a.org", "rama"
FQDN = f"{HOST}.{DOMAIN}"


def _setup(repo: config.SecretsRepo, admin_key, *, kdc_role=True,
           named_keytab=False):
    keypair = add_host(repo, HOST, services=["host"])
    repo.set_role_config(config.RoleConfig(name=f"domain-{DOMAIN}", hosts=[HOST]))

    repo.realm_principals_path(REALM).mkdir(parents=True, exist_ok=True)
    realm_config = realm_mod.RealmConfig(name=REALM, domains=[DOMAIN])
    admin_keys = [admin_key.public_key]
    crypto.encrypt_age(b"fake-realm-key", admin_keys, repo.realm_key_path(REALM))
    for stem in [f"host_{FQDN}", f"kadmin_admin@{REALM}",
                 f"kadmin_changepw@{REALM}"]:
        crypto.encrypt_age(f"key-{stem}\n".encode(), admin_keys,
                           repo.realm_principals_path(REALM) / f"{stem}.age")
    if named_keytab:
        realm_config.principals[f"host/{FQDN}"] = realm_mod.classify(
            f"host/{FQDN}", REALM)
        realm_config.keytabs["web"] = realm_mod.KeytabSpec(
            principals=[f"host/{FQDN}"], hosts=[HOST])
    realm_mod.save(repo, realm_config)

    if kdc_role:
        _init_role(repo, "kdc")
    return keypair


def _init_role(repo, role):
    result = runner.invoke(app, ["role", "init", role, "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)


def _stub_kdc(monkeypatch, *, key=b"k" * 32):
    """ext_keytab stand-ins that, like Heimdal, stamp a fresh time every call."""
    clock = iter(range(1_000_000, 2_000_000))

    def keytab_for(principals):
        return _keytab(*(_entry(p.split("@")[0], REALM, timestamp=next(clock), key=key)
                         for p in principals))

    def fake_instantiate(realm, realm_data_path, etypes=None, verbose=False):
        return Path("/fake/kdc.conf")

    def fake_extract_host(hostname, kdc_conf_path, output_path, services=None,
                          all_keys=False, verbose=False):
        output_path.write_bytes(keytab_for([f"{s}/{hostname}" for s in services]))
        return output_path

    def fake_extract(principals, kdc_conf_path, output_path, verbose=False):
        output_path.write_bytes(keytab_for(principals))
        return output_path

    monkeypatch.setattr(krb, "instantiate_realm", fake_instantiate)
    monkeypatch.setattr(krb, "extract_host_keytab", fake_extract_host)
    monkeypatch.setattr(krb, "extract_keytab", fake_extract)


def _build(repo):
    result = runner.invoke(app, [
        "build", "keytabs", "--realm", REALM, "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)
    return result


def _snapshot(repo) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in sorted(repo.deploy_path.rglob("*.age"))}


def test_second_build_rewrites_nothing(repo, admin_key, monkeypatch):
    _setup(repo, admin_key, named_keytab=True)
    _stub_kdc(monkeypatch)
    _build(repo)
    before = _snapshot(repo)

    # Everything the build produces from the realm: the host keytab, the
    # named keytab's copy, the KDC daemon keytabs, bundle and realm key.
    names = {p.name for p in before}
    assert "keytab.age" in names
    assert any("web" in p.name for p in before), names
    for suffix in ["-principals.age", "-realm-key.age",
                   "-kadmind.keytab.age", "-kpasswdd.keytab.age"]:
        assert f"{REALM}{suffix}" in names, names

    result = _build(repo)

    after = _snapshot(repo)
    changed = sorted(str(p.relative_to(repo.deploy_path))
                     for p in before if before[p] != after.get(p))
    assert changed == [], f"rewritten without a content change: {changed}"
    assert "Wrote" not in _out(result)
    assert "Keytab unchanged" in _out(result)


def test_a_changed_key_is_still_rewritten(repo, admin_key, monkeypatch):
    keypair = _setup(repo, admin_key)
    _stub_kdc(monkeypatch)
    _build(repo)
    keytab_path = repo.host_deploy_path(HOST) / "keytab.age"
    before = keytab_path.read_bytes()

    _stub_kdc(monkeypatch, key=b"r" * 32)   # a rekey
    _build(repo)

    assert keytab_path.read_bytes() != before
    plain = crypto.decrypt_age_bytes(keytab_path, identity_content=keypair.private_key)
    assert b"r" * 32 in plain


def test_a_new_recipient_gets_the_file_rewritten(repo, admin_key, monkeypatch):
    """Built before the KDC role existed, the host keytab lacks the KDC as a
    recipient. Unchanged content must not keep it that way."""
    _setup(repo, admin_key, kdc_role=False)
    _stub_kdc(monkeypatch)
    _build(repo)
    keytab_path = repo.host_deploy_path(HOST) / "keytab.age"
    assert crypto.recipients_of(keytab_path) == 2

    _init_role(repo, "kdc")
    _build(repo)

    assert crypto.recipients_of(keytab_path) == 3


# Against a real Heimdal -------------------------------------------------------

@requires("ruby", "kadmin", "kstash")
def test_real_heimdal_rebuild_is_a_no_op(repo, admin_key, tmp_path, monkeypatch):
    """The whole point, end to end: real ext_keytab, real timestamps."""
    krb5_conf = tmp_path / "krb5.conf"
    krb5_conf.write_text(f"[libdefaults]\n default_realm = {REALM}\n")
    monkeypatch.setenv("KRB5_CONFIG", str(krb5_conf))

    add_host(repo, HOST, services=["host"])
    repo.set_role_config(config.RoleConfig(name=f"domain-{DOMAIN}", hosts=[HOST]))
    _init_role(repo, "kdc")
    result = runner.invoke(app, [
        "realm", "init", REALM, "--domain", DOMAIN, "--secrets-path", str(repo.path)])
    if result.exit_code != 0:
        pytest.skip(f"could not initialise a Heimdal realm here: {_out(result)}")

    _build(repo)
    keytab_path = repo.host_deploy_path(HOST) / "keytab.age"
    assert keytab_path.exists()
    before = _snapshot(repo)

    import time
    time.sleep(1.1)   # make sure ext_keytab's timestamps would differ
    _build(repo)

    after = _snapshot(repo)
    assert [p for p in before if before[p] != after.get(p)] == []
