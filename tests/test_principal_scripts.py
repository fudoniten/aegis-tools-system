"""kdc-add-principal.rb / kdc-rekey-principal.rb against a stand-in kadmin.

Heimdal's dump always names principals fully qualified, while the principal
given to `aegis realm add-principal` usually is not. These run the real Ruby
scripts with a fake `kadmin` on PATH that only knows how to `dump`, so the
matching between the two is exercised without a KDC.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from aegis import kerberos as krb

pytestmark = pytest.mark.skipif(shutil.which("ruby") is None, reason="ruby not installed")

DUMP = (
    "nfs/files.burg.fudo.org@BURG.FUDO.ORG 1::17:abc:-:0 created::0:\n"
    "host/other.burg.fudo.org@BURG.FUDO.ORG 1::17:def:-:0 created::0:\n"
)


@pytest.fixture
def fake_kadmin(tmp_path: Path, monkeypatch) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    dump = tmp_path / "dump.txt"
    dump.write_text(DUMP)
    script = bindir / "kadmin"
    # `dump --decrypt FILE` writes the canned dump; everything else succeeds.
    script.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do last="$a"; done\n'
        'case " $* " in *" dump "*) cp "%s" "$last" ;; esac\n' % dump
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    conf = tmp_path / "kdc.conf"
    conf.write_text("")
    return conf


def _principals_dir(tmp_path: Path) -> Path:
    d = tmp_path / "principals"
    d.mkdir()
    return d


@pytest.mark.parametrize(
    "principal", ["nfs/files.burg.fudo.org", "nfs/files.burg.fudo.org@BURG.FUDO.ORG"])
def test_add_principal_writes_key_for_unqualified_and_qualified(
        tmp_path: Path, fake_kadmin: Path, principal: str):
    out = krb.add_principal(principal, fake_kadmin, _principals_dir(tmp_path))
    lines = out.read_text().splitlines()
    assert lines == [DUMP.splitlines()[0]]


def test_add_principal_fails_rather_than_writing_empty_key(
        tmp_path: Path, fake_kadmin: Path):
    principals = _principals_dir(tmp_path)
    with pytest.raises(subprocess.CalledProcessError):
        krb.add_principal("nfs/missing.burg.fudo.org", fake_kadmin, principals)
    assert list(principals.iterdir()) == []


def test_add_principal_does_not_match_another_realm(
        tmp_path: Path, fake_kadmin: Path):
    with pytest.raises(subprocess.CalledProcessError):
        krb.add_principal(
            "nfs/files.burg.fudo.org@OTHER.REALM", fake_kadmin,
            _principals_dir(tmp_path))


def test_rekey_principal_accepts_unqualified(tmp_path: Path, fake_kadmin: Path):
    principals = _principals_dir(tmp_path)
    (principals / "nfs_files.burg.fudo.org.key").write_text("old\n")
    out = krb.rekey_principal("nfs/files.burg.fudo.org", fake_kadmin, principals)
    assert out.read_text().splitlines() == [DUMP.splitlines()[0]]
