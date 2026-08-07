"""Host lifecycle status.

Not every host in the repo is a machine waiting for secrets: some are
declared before they exist, some are gone, and some are real but served by
something other than Aegis.  Without a way to say which, "no master key" can
only be read as "broken", and the permanent errors that produces are what
teaches an operator to stop reading `aegis check`.
"""

import pytest
from typer.testing import CliRunner

from aegis import config
from aegis.cli import app
from aegis.cli_check import SEVERITY_INFO, run_check
from aegis.errors import ConfigError

from .conftest import add_host

runner = CliRunner()


def out(result) -> str:
    return result.output


def statuses(report):
    return {(f.scope, f.severity) for f in report.findings}


# Model -------------------------------------------------------------------

def test_status_defaults_to_active(repo):
    add_host(repo, "rama")
    assert repo.get_host_config("rama").status == config.STATUS_ACTIVE
    assert repo.get_host_config("rama").deploys


def test_unknown_status_is_an_error_not_a_default(repo):
    """A typo must not read as 'active' and quietly resume deliveries."""
    add_host(repo, "rama")
    path = repo.src_path / "hosts" / "rama.toml"
    path.write_text('status = "retried"\n' + path.read_text())

    with pytest.raises(ConfigError) as excinfo:
        repo.get_host_config("rama")
    assert "retried" in str(excinfo.value)


def test_status_round_trips(repo):
    add_host(repo, "clunk")
    host = repo.get_host_config("clunk")
    host.status = config.STATUS_PENDING
    host.note = "realm never fleshed out"
    repo.set_host_config(host)

    reloaded = repo.get_host_config("clunk")
    assert reloaded.status == config.STATUS_PENDING
    assert reloaded.note == "realm never fleshed out"
    assert not reloaded.deploys


def test_active_hosts_omit_the_status_key(repo):
    """Existing host files must not churn just because the field exists."""
    add_host(repo, "rama")
    assert "status" not in (repo.src_path / "hosts" / "rama.toml").read_text()


def test_list_deploying_hosts_excludes_the_others(repo):
    add_host(repo, "rama")
    for name, status in [
        ("clunk", config.STATUS_PENDING),
        ("pselby-work", config.STATUS_RETIRED),
        ("paris", config.STATUS_EXTERNAL),
    ]:
        add_host(repo, name)
        host = repo.get_host_config(name)
        host.status = status
        repo.set_host_config(host)

    assert repo.list_deploying_hosts() == ["rama"]
    assert len(repo.list_hosts()) == 4


# check -------------------------------------------------------------------

def test_missing_master_key_on_an_active_host_is_an_error(repo):
    repo.set_host_config(config.HostConfig(hostname="rama"))
    report = run_check(repo)
    assert ("host/rama", "error") in statuses(report)


@pytest.mark.parametrize(
    "status", [config.STATUS_PENDING, config.STATUS_RETIRED, config.STATUS_EXTERNAL])
def test_declared_status_downgrades_the_missing_key_error(repo, status):
    """The whole point: these must not sit in the output as permanent errors."""
    repo.set_host_config(config.HostConfig(hostname="clunk", status=status))

    report = run_check(repo)
    findings = [f for f in report.findings if f.scope == "host/clunk"]
    assert len(findings) == 1
    assert findings[0].severity == SEVERITY_INFO
    assert status in findings[0].message
    assert not report.errors


def test_note_is_shown_so_the_reason_lives_with_the_exclusion(repo):
    repo.set_host_config(config.HostConfig(
        hostname="pselby-work",
        status=config.STATUS_RETIRED,
        note="laptop returned",
    ))
    report = run_check(repo)
    finding = next(f for f in report.findings if f.scope == "host/pselby-work")
    assert "laptop returned" in finding.message


def test_leftover_secrets_on_an_unmanaged_host_are_an_error(repo):
    """Excluding a host is not the same as cleaning up after it."""
    keypair = add_host(repo, "pselby-work")
    host = repo.get_host_config("pselby-work")
    host.status = config.STATUS_RETIRED
    repo.set_host_config(host)

    deploy = repo.host_deploy_path("pselby-work")
    (deploy / "ssh").mkdir(parents=True)
    (deploy / "ssh" / "ssh_host_ed25519_key.age").write_text("x")

    report = run_check(repo)
    finding = next(f for f in report.findings if f.scope == "host/pselby-work")
    assert finding.severity == "error"
    assert "still deployed" in finding.message
    # A retired host's key still opens every copy it already has.
    assert "can still read them" in finding.message


def test_info_findings_do_not_fail_the_check(repo):
    add_host(repo, "rama")
    repo.set_host_config(config.HostConfig(
        hostname="paris", status=config.STATUS_EXTERNAL))

    result = runner.invoke(app, ["check", "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, out(result)
    assert "not managed" in out(result)


# CLI ---------------------------------------------------------------------

def test_set_host_status_records_status_and_note(repo):
    add_host(repo, "pselby-work")
    result = runner.invoke(app, [
        "host", "set-status", "pselby-work", "retired",
        "--note", "laptop returned",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, out(result)

    host = repo.get_host_config("pselby-work")
    assert host.status == config.STATUS_RETIRED
    assert host.note == "laptop returned"


def test_set_host_status_rejects_an_unknown_status(repo):
    add_host(repo, "rama")
    result = runner.invoke(app, [
        "host", "set-status", "rama", "decommissioned",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 1
    assert repo.get_host_config("rama").status == config.STATUS_ACTIVE


def test_set_host_status_warns_about_material_it_did_not_remove(repo):
    add_host(repo, "pselby-work")
    deploy = repo.host_deploy_path("pselby-work")
    deploy.mkdir(parents=True, exist_ok=True)
    (deploy / "nexus-key.age").write_text("x")

    result = runner.invoke(app, [
        "host", "set-status", "pselby-work", "retired",
        "--secrets-path", str(repo.path),
    ])
    assert result.exit_code == 0, out(result)
    assert "Nothing was removed" in out(result)
    assert "rotate" in out(result)


def test_build_role_keys_skips_unmanaged_hosts(repo):
    """A role may name a host that does not exist yet; it gets no key."""
    add_host(repo, "rama")
    add_host(repo, "clunk")
    host = repo.get_host_config("clunk")
    host.status = config.STATUS_PENDING
    repo.set_host_config(host)

    runner.invoke(app, [
        "role", "init", "domain-sea.fudo.org", "--secrets-path", str(repo.path)])
    for h in ("rama", "clunk"):
        result = runner.invoke(app, [
            "role", "add-host", "domain-sea.fudo.org", h,
            "--secrets-path", str(repo.path)])
        assert result.exit_code == 0, out(result)

    result = runner.invoke(app, [
        "build", "role-keys", "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, out(result)

    assert repo.host_role_key_path("rama", "domain-sea.fudo.org").exists()
    assert not repo.host_role_key_path("clunk", "domain-sea.fudo.org").exists()
