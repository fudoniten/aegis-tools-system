"""Named keytabs: an arbitrary principal list, delivered wherever declared.

The host keytab every realm member gets is implicit and holds that host's own
service principals. A named keytab is the explicit form, and the behaviour
worth pinning down is what follows from the *declaration*: which manifests
mention it, which ciphertexts should exist, and what happens when it names
something that does not.

Building a keytab needs a live Heimdal database, so extraction itself is not
exercised here -- these tests cover the declaration, delivery and manifest
layers, which is where the decisions live.
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegis import cli_check, config, host_secrets, realm as realm_mod
from aegis.cli import app

from .conftest import add_host, requires

runner = CliRunner()


def _out(result):
    return (result.stdout or "") + (getattr(result, "stderr", None) or "")


def _make_realm(
    repo: config.SecretsRepo,
    name: str = "SEA.FUDO.ORG",
    domains: list[str] | None = None,
) -> None:
    repo.realm_principals_path(name).mkdir(parents=True, exist_ok=True)
    realm_mod.save(repo, realm_mod.RealmConfig(
        name=name, domains=domains if domains is not None else ["sea.fudo.org"]))


def _store_principal(repo: config.SecretsRepo, realm: str, principal: str) -> None:
    """Pretend a principal exists, without needing a KDC to make one."""
    stem = realm_mod.principal_filename(principal)
    path = repo.realm_principals_path(realm) / f"{stem}.age"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN AGE ENCRYPTED FILE-----\n")

    realm_config = realm_mod.load(repo, realm)
    realm_config.principals[principal] = realm_mod.classify(principal, realm)
    realm_mod.save(repo, realm_config)


def _declare(
    repo: config.SecretsRepo,
    name: str,
    principals: list[str],
    *,
    realm: str = "SEA.FUDO.ORG",
    hosts: list[str] | None = None,
    roles: list[str] | None = None,
) -> None:
    realm_config = realm_mod.load(repo, realm)
    realm_config.keytabs[name] = realm_mod.KeytabSpec(
        principals=principals, hosts=hosts or [], roles=roles or [])
    realm_mod.save(repo, realm_config)


def _init_role(repo: config.SecretsRepo, role: str) -> None:
    result = runner.invoke(app, [
        "role", "init", role, "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)


def _build_ciphertext(path: Path) -> None:
    """Stand in for what 'aegis build keytabs' would have written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("-----BEGIN AGE ENCRYPTED FILE-----\n")


# Declaration ------------------------------------------------------------


def test_spec_roundtrips_through_realm_toml(repo: config.SecretsRepo):
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/hermes.sea.fudo.org"],
             hosts=["nostromo"], roles=["agent"])

    loaded = realm_mod.load(repo, "SEA.FUDO.ORG")

    spec = loaded.keytabs["hermes"]
    assert spec.principals == ["hermes/hermes.sea.fudo.org"]
    assert spec.hosts == ["nostromo"]
    assert spec.roles == ["agent"]
    assert not spec.export_only


def test_keytab_with_no_recipient_is_export_only(repo: config.SecretsRepo):
    """The mode for a consumer aegis does not deploy to, e.g. a k8s workload."""
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/hermes.sea.fudo.org"])

    spec = realm_mod.load(repo, "SEA.FUDO.ORG").keytabs["hermes"]

    assert spec.export_only


def test_new_rejects_unknown_host(repo: config.SecretsRepo):
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")

    result = runner.invoke(app, [
        "keytab", "new", "hermes", "--realm", "SEA.FUDO.ORG",
        "--principal", "hermes/h.sea.fudo.org", "--host", "nope",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert "unknown host" in _out(result)


def test_new_rejects_principal_that_does_not_exist(repo: config.SecretsRepo):
    """Without --create-missing, a typo is caught before anything is declared."""
    _make_realm(repo)

    result = runner.invoke(app, [
        "keytab", "new", "hermes", "--realm", "SEA.FUDO.ORG",
        "--principal", "hermes/typo.sea.fudo.org",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert "not in realm" in _out(result)
    assert "hermes" not in realm_mod.load(repo, "SEA.FUDO.ORG").keytabs


def test_new_declares_an_export_only_keytab(repo: config.SecretsRepo):
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")

    result = runner.invoke(app, [
        "keytab", "new", "hermes", "--realm", "SEA.FUDO.ORG",
        "--principal", "hermes/h.sea.fudo.org",
        "--note", "k8s workload",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 0, _out(result)
    spec = realm_mod.load(repo, "SEA.FUDO.ORG").keytabs["hermes"]
    assert spec.principals == ["hermes/h.sea.fudo.org"]
    assert spec.note == "k8s workload"
    assert spec.export_only
    assert "export only" in _out(result)


def test_names_are_unique_across_realms(repo: config.SecretsRepo):
    """Delivery is by name, so two realms claiming one is unresolvable."""
    _make_realm(repo, "A.ORG", domains=["a.org"])
    _make_realm(repo, "B.ORG", domains=["b.org"])
    _store_principal(repo, "A.ORG", "svc/a.a.org")
    _store_principal(repo, "B.ORG", "svc/b.b.org")
    _declare(repo, "shared", ["svc/a.a.org"], realm="A.ORG")

    result = runner.invoke(app, [
        "keytab", "new", "shared", "--realm", "B.ORG",
        "--principal", "svc/b.b.org", "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert "already declared by realm A.ORG" in _out(result)


def test_find_keytab_refuses_to_guess_between_realms(repo: config.SecretsRepo):
    """A repo that got into the ambiguous state fails loudly rather than picks."""
    _make_realm(repo, "A.ORG", domains=["a.org"])
    _make_realm(repo, "B.ORG", domains=["b.org"])
    _declare(repo, "shared", ["svc/a.a.org"], realm="A.ORG")
    _declare(repo, "shared", ["svc/b.b.org"], realm="B.ORG")

    with pytest.raises(realm_mod.RealmError, match="more than one realm"):
        realm_mod.find_keytab(repo, "shared")


# Manifest reconciliation -------------------------------------------------


def test_host_delivered_keytab_reaches_the_manifest(repo: config.SecretsRepo):
    add_host(repo, "nostromo")
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])
    _build_ciphertext(repo.host_keytab_path("nostromo", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    entry = manifest.keytabs["hermes"]
    assert entry.source == "keytabs/hermes.age"
    assert entry.target == "/run/aegis/keytabs/hermes"
    assert entry.role is None


def test_role_delivered_keytab_points_out_of_the_host_directory(
    repo: config.SecretsRepo,
):
    """One ciphertext for the role, named by every member's manifest."""
    add_host(repo, "nostromo")
    _init_role(repo, "agent")
    runner.invoke(app, [
        "role", "add-host", "agent", "nostromo", "--secrets-path", str(repo.path)])
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], roles=["agent"])
    _build_ciphertext(repo.role_keytab_path("agent", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    entry = manifest.keytabs["hermes"]
    assert entry.source == "../../roles/agent/keytabs/hermes.age"
    assert entry.role == "agent"


def test_export_only_keytab_reaches_no_manifest(repo: config.SecretsRepo):
    add_host(repo, "nostromo")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])
    _build_ciphertext(repo.export_keytab_path("hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    assert manifest.keytabs == {}


def test_unbuilt_keytab_is_not_declared(repo: config.SecretsRepo):
    """A manifest naming a file that is not there fails the host's next boot."""
    add_host(repo, "nostromo")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    assert manifest.keytabs == {}


def test_leaving_a_role_drops_the_keytab_entry(repo: config.SecretsRepo):
    """Otherwise the host points at a file it can no longer decrypt."""
    add_host(repo, "nostromo")
    _init_role(repo, "agent")
    runner.invoke(app, [
        "role", "add-host", "agent", "nostromo", "--secrets-path", str(repo.path)])
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], roles=["agent"])
    _build_ciphertext(repo.role_keytab_path("agent", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)
    assert "hermes" in manifest.keytabs

    runner.invoke(app, [
        "role", "remove-host", "agent", "nostromo",
        "--secrets-path", str(repo.path)])
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    assert manifest.keytabs == {}


def test_placement_moves_a_named_keytab(repo: config.SecretsRepo):
    add_host(repo, "nostromo")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])
    _build_ciphertext(repo.host_keytab_path("nostromo", "hermes"))

    result = runner.invoke(app, [
        "host", "set-placement", "nostromo", "keytab:hermes",
        "--target", "/run/hermes/krb5.keytab", "--user", "hermes",
        "--mode", "0400", "--secrets-path", str(repo.path)])
    assert result.exit_code == 0, _out(result)

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    entry = manifest.keytabs["hermes"]
    assert entry.target == "/run/hermes/krb5.keytab"
    assert entry.user == "hermes"
    assert entry.mode == "0400"


def test_host_copy_wins_over_role_copy(repo: config.SecretsRepo):
    """Granted twice by two routes: the more specific one is kept, loudly."""
    add_host(repo, "nostromo")
    _init_role(repo, "agent")
    runner.invoke(app, [
        "role", "add-host", "agent", "nostromo", "--secrets-path", str(repo.path)])
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"],
             hosts=["nostromo"], roles=["agent"])
    _build_ciphertext(repo.host_keytab_path("nostromo", "hermes"))
    _build_ciphertext(repo.role_keytab_path("agent", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    conflicts = host_secrets.reconcile_keytabs(repo, "nostromo", manifest)

    assert manifest.keytabs["hermes"].role is None
    assert any("directly and through role" in c for c in conflicts)


# Checking ---------------------------------------------------------------


def test_check_flags_a_principal_that_does_not_exist(repo: config.SecretsRepo):
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/ghost.sea.fudo.org"])

    report = cli_check.run_check(repo)

    assert any(
        f.scope == "keytab/hermes" and "not stored" in f.message
        for f in report.errors)


def test_check_flags_an_unbuilt_keytab(repo: config.SecretsRepo):
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])

    report = cli_check.run_check(repo)

    assert any(
        f.scope == "keytab/hermes" and "not built" in f.message
        for f in report.warnings)


def test_check_passes_on_a_built_export_keytab(repo: config.SecretsRepo):
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])
    _build_ciphertext(repo.export_keytab_path("hermes"))

    report = cli_check.run_check(repo)

    assert not [f for f in report.findings if f.scope == "keytab/hermes"]


def test_check_warns_when_an_exported_keytab_is_mid_rotation(
    repo: config.SecretsRepo,
):
    """Nothing rebuilds a keytab that left by hand; someone has to re-export."""
    _make_realm(repo)
    principal = "hermes/h.sea.fudo.org"
    _store_principal(repo, "SEA.FUDO.ORG", principal)
    _declare(repo, "hermes", [principal])
    _build_ciphertext(repo.export_keytab_path("hermes"))

    previous = repo.realm_previous_principals_path("SEA.FUDO.ORG")
    previous.mkdir(parents=True, exist_ok=True)
    (previous / f"{realm_mod.principal_filename(principal)}.age").write_text("x")

    report = cli_check.run_check(repo)

    assert any(
        f.scope == "keytab/hermes" and "re-exported by hand" in f.message
        for f in report.warnings)


def test_check_flags_a_duplicate_name(repo: config.SecretsRepo):
    _make_realm(repo, "A.ORG", domains=["a.org"])
    _make_realm(repo, "B.ORG", domains=["b.org"])
    _declare(repo, "shared", [], realm="A.ORG")
    _declare(repo, "shared", [], realm="B.ORG")

    report = cli_check.run_check(repo)

    assert any(
        f.scope == "keytab/shared" and "more than one realm" in f.message
        for f in report.errors)


# Recipients --------------------------------------------------------------


def test_role_keytab_is_encrypted_to_the_role(repo: config.SecretsRepo):
    from aegis import admin, recipients

    _init_role(repo, "agent")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], roles=["agent"])
    path = repo.role_keytab_path("agent", "hermes")
    _build_ciphertext(path)

    policies = recipients.plan(repo, admin.recipients(repo))
    policy = next(p for p in policies if p.path == path)

    role_key = repo.role_pubkey_path("agent").read_text().strip()
    assert policy.category == recipients.CAT_ROLE
    assert role_key in policy.recipients
    assert policy.resolvable


def test_export_keytab_is_admin_only(repo: config.SecretsRepo):
    from aegis import admin, recipients

    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])
    path = repo.export_keytab_path("hermes")
    _build_ciphertext(path)

    policies = recipients.plan(repo, admin.recipients(repo))
    policy = next(p for p in policies if p.path == path)

    assert policy.category == recipients.CAT_ADMIN_ONLY
    assert policy.recipients == admin.recipients(repo)


def test_host_keytab_does_not_get_the_kdc_role_key(repo: config.SecretsRepo):
    """A named keytab is not the host keytab: the KDC has no reason to read it."""
    from aegis import admin, recipients

    host_key = add_host(repo, "nostromo")
    assert host_key is not None
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])
    path = repo.host_keytab_path("nostromo", "hermes")
    _build_ciphertext(path)

    policies = recipients.plan(repo, admin.recipients(repo))
    policy = next(p for p in policies if p.path == path)

    assert policy.category == recipients.CAT_HOST
    assert set(policy.recipients) == {host_key.public_key, *admin.recipients(repo)}


# Removal -----------------------------------------------------------------


def test_removing_a_host_is_blocked_while_a_keytab_names_it(
    repo: config.SecretsRepo,
):
    from aegis import removal

    add_host(repo, "nostromo")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])

    plan = removal.plan_host_removal(repo, "nostromo")

    assert any("keytab 'hermes'" in b for b in plan.blockers)


def test_removing_a_role_is_blocked_while_a_keytab_uses_it(
    repo: config.SecretsRepo,
):
    from aegis import removal

    _init_role(repo, "agent")
    _make_realm(repo)
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], roles=["agent"])

    plan = removal.plan_role_removal(repo, "agent")

    assert any("keytab 'hermes'" in b for b in plan.blockers)


# Exporting ---------------------------------------------------------------

needs_age = requires("age")


@needs_age
def test_export_writes_the_keytab_private(
    repo: config.SecretsRepo, tmp_path: Path
):
    """The handoff for a consumer aegis does not deploy to, e.g. Kubernetes."""
    from aegis import admin, crypto

    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])

    out = repo.export_keytab_path("hermes")
    out.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(b"\x05\x02keytab-bytes", admin.recipients(repo), out)

    destination = tmp_path / "hermes.keytab"
    result = runner.invoke(app, [
        "keytab", "export", "hermes", "--output", str(destination),
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 0, _out(result)
    # Binary-clean: a keytab is not text, and a mangled one fails at kinit.
    assert destination.read_bytes() == b"\x05\x02keytab-bytes"
    assert oct(destination.stat().st_mode)[-3:] == "600"


@needs_age
def test_export_refuses_to_clobber_without_force(
    repo: config.SecretsRepo, tmp_path: Path
):
    from aegis import admin, crypto

    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])
    out = repo.export_keytab_path("hermes")
    out.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(b"keytab", admin.recipients(repo), out)

    destination = tmp_path / "hermes.keytab"
    destination.write_text("do not lose me")

    result = runner.invoke(app, [
        "keytab", "export", "hermes", "--output", str(destination),
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 1
    assert destination.read_text() == "do not lose me"


def test_export_of_an_unbuilt_keytab_says_how_to_build_it(
    repo: config.SecretsRepo, tmp_path: Path
):
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"])

    result = runner.invoke(app, [
        "keytab", "export", "hermes", "--output", str(tmp_path / "k"),
        "--secrets-path", str(repo.path)])

    # Raised as an AegisError rather than printed here: aegis.cli.main is what
    # turns one into a one-line message, and CliRunner bypasses it.
    assert result.exit_code != 0
    assert "aegis build keytabs" in str(result.exception)


def test_remove_host_drops_the_manifest_entry(repo: config.SecretsRepo):
    """Between removal and the next build, a stale entry fails the host's boot."""
    add_host(repo, "nostromo")
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], hosts=["nostromo"])
    _build_ciphertext(repo.host_keytab_path("nostromo", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    result = runner.invoke(app, [
        "keytab", "remove-host", "hermes", "nostromo",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 0, _out(result)
    assert not repo.host_keytab_path("nostromo", "hermes").exists()
    reloaded = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    assert reloaded.keytabs == {}


def test_remove_role_drops_every_member_manifest(repo: config.SecretsRepo):
    add_host(repo, "nostromo")
    _init_role(repo, "agent")
    runner.invoke(app, [
        "role", "add-host", "agent", "nostromo", "--secrets-path", str(repo.path)])
    _make_realm(repo)
    _store_principal(repo, "SEA.FUDO.ORG", "hermes/h.sea.fudo.org")
    _declare(repo, "hermes", ["hermes/h.sea.fudo.org"], roles=["agent"])
    _build_ciphertext(repo.role_keytab_path("agent", "hermes"))

    manifest = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    host_secrets.reconcile_keytabs(repo, "nostromo", manifest)
    host_secrets.save_host_manifest(repo.deploy_path, manifest)

    result = runner.invoke(app, [
        "keytab", "remove-role", "hermes", "agent",
        "--secrets-path", str(repo.path)])

    assert result.exit_code == 0, _out(result)
    reloaded = host_secrets.load_host_manifest(repo.deploy_path, "nostromo")
    assert reloaded.keytabs == {}
