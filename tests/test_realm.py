"""Tests for realm metadata and host/realm resolution."""

from pathlib import Path

from aegis import config, realm as realm_mod


def _make_realm(repo: config.SecretsRepo, name: str, domains: list[str]) -> None:
    repo.realm_principals_path(name).mkdir(parents=True, exist_ok=True)
    realm_mod.save(repo, realm_mod.RealmConfig(name=name, domains=domains))


def test_realm_config_roundtrip(repo: config.SecretsRepo):
    _make_realm(repo, "SEA.FUDO.ORG", ["sea.fudo.org"])
    realm_mod.save(repo, realm_mod.RealmConfig(
        name="SEA.FUDO.ORG",
        domains=["sea.fudo.org"],
        trusts=["INFORMIS.LAND"],
        kdc_role="kdc",
        etypes=["aes256-cts-hmac-sha1-96"],
        principals={
            "postgres/rama.sea.fudo.org": realm_mod.PrincipalEntry(
                kind=realm_mod.KIND_SERVICE, host="rama"),
        },
    ))

    loaded = realm_mod.load(repo, "SEA.FUDO.ORG")

    assert loaded.domains == ["sea.fudo.org"]
    assert loaded.trusts == ["INFORMIS.LAND"]
    assert loaded.etypes == ["aes256-cts-hmac-sha1-96"]
    assert loaded.principals["postgres/rama.sea.fudo.org"].host == "rama"


def test_missing_realm_toml_yields_defaults(repo: config.SecretsRepo):
    """Realms imported before realm.toml existed still load."""
    repo.realm_principals_path("OLD.REALM").mkdir(parents=True)

    loaded = realm_mod.load(repo, "OLD.REALM")

    assert loaded.name == "OLD.REALM"
    assert loaded.etypes == realm_mod.DEFAULT_ETYPES
    assert loaded.domains == []


def test_principal_filename_convention():
    """Matches the Ruby tooling: every '/' becomes '_'."""
    assert realm_mod.principal_filename(
        "host/foo.example.com") == "host_foo.example.com"
    assert realm_mod.principal_filename(
        "krbtgt/A.ORG@B.ORG") == "krbtgt_A.ORG@B.ORG"


def test_principal_from_filename_prefers_index():
    """The canonical name in realm.toml beats the lossy filename guess."""
    index = {"WELLKNOWN/org.h5l.fast-cookie@WELLKNOWN:ORG.H5L":
             realm_mod.PrincipalEntry()}
    stem = "WELLKNOWN_org.h5l.fast-cookie@WELLKNOWN:ORG.H5L"

    assert realm_mod.principal_from_filename(stem, index) == (
        "WELLKNOWN/org.h5l.fast-cookie@WELLKNOWN:ORG.H5L")


def test_principal_from_filename_falls_back():
    assert realm_mod.principal_from_filename(
        "host_foo.example.com", {}) == "host/foo.example.com"


def test_classify_own_krbtgt_is_infrastructure():
    entry = realm_mod.classify("krbtgt/SEA.FUDO.ORG@SEA.FUDO.ORG", "SEA.FUDO.ORG")
    assert entry.kind == realm_mod.KIND_INFRASTRUCTURE


def test_classify_cross_realm_identifies_peer():
    entry = realm_mod.classify("krbtgt/INFORMIS.LAND@SEA.FUDO.ORG", "SEA.FUDO.ORG")
    assert entry.kind == realm_mod.KIND_CROSS_REALM
    assert entry.peer == "INFORMIS.LAND"

    # ...from the other realm's point of view the peer is the other one
    entry = realm_mod.classify("krbtgt/INFORMIS.LAND@SEA.FUDO.ORG", "INFORMIS.LAND")
    assert entry.kind == realm_mod.KIND_CROSS_REALM
    assert entry.peer == "SEA.FUDO.ORG"


def test_classify_admin_principals():
    for principal in ("kadmin/admin@X", "changepw/kerberos@X", "default@X"):
        assert realm_mod.classify(principal, "X").kind == realm_mod.KIND_INFRASTRUCTURE


def test_classify_service_principal():
    entry = realm_mod.classify("postgres/rama.sea.fudo.org", "SEA.FUDO.ORG")
    assert entry.kind == realm_mod.KIND_SERVICE


def test_host_resolves_to_realm_via_domain_role(repo: config.SecretsRepo):
    """host --(domain-* role)--> domain --(realm.toml)--> realm."""
    _make_realm(repo, "SEA.FUDO.ORG", ["sea.fudo.org"])
    repo.set_host_config(config.HostConfig(hostname="rama", age_pubkey="age1x"))
    repo.set_role_config(config.RoleConfig(
        name="domain-sea.fudo.org", hosts=["rama"]))

    grouped = realm_mod.hosts_by_realm(repo)

    assert list(grouped) == ["SEA.FUDO.ORG"]
    member = grouped["SEA.FUDO.ORG"][0]
    assert member.hostname == "rama"
    assert member.domain == "sea.fudo.org"
    assert member.fqdn == "rama.sea.fudo.org"


def test_host_without_domain_role_resolves_to_nothing(repo: config.SecretsRepo):
    _make_realm(repo, "SEA.FUDO.ORG", ["sea.fudo.org"])
    repo.set_host_config(config.HostConfig(hostname="orphan", age_pubkey="age1x"))

    assert realm_mod.hosts_by_realm(repo) == {}


def test_realm_without_declared_domains_claims_no_hosts(repo: config.SecretsRepo):
    """This was the state of the repo: domain roles populated, realms silent."""
    _make_realm(repo, "SEA.FUDO.ORG", [])
    repo.set_host_config(config.HostConfig(hostname="rama", age_pubkey="age1x"))
    repo.set_role_config(config.RoleConfig(
        name="domain-sea.fudo.org", hosts=["rama"]))

    assert realm_mod.hosts_by_realm(repo) == {}


def test_host_in_two_domains_gets_two_memberships(repo: config.SecretsRepo):
    """Legitimate: the host gets a principal in each realm."""
    _make_realm(repo, "SEA.FUDO.ORG", ["sea.fudo.org"])
    _make_realm(repo, "INFORMIS.LAND", ["informis.land"])
    repo.set_host_config(config.HostConfig(hostname="dual", age_pubkey="age1x"))
    repo.set_role_config(config.RoleConfig(
        name="domain-sea.fudo.org", hosts=["dual"]))
    repo.set_role_config(config.RoleConfig(
        name="domain-informis.land", hosts=["dual"]))

    grouped = realm_mod.hosts_by_realm(repo)

    assert set(grouped) == {"SEA.FUDO.ORG", "INFORMIS.LAND"}
    fqdns = {m.fqdn for members in grouped.values() for m in members}
    assert fqdns == {"dual.sea.fudo.org", "dual.informis.land"}


def test_realm_of_domain(repo: config.SecretsRepo):
    _make_realm(repo, "SEA.FUDO.ORG", ["sea.fudo.org"])

    assert realm_mod.realm_of_domain(repo, "sea.fudo.org") == "SEA.FUDO.ORG"
    assert realm_mod.realm_of_domain(repo, "elsewhere.org") is None
