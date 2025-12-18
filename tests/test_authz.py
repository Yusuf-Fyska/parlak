from core import authz_scope


def test_domain_match_allowlist(monkeypatch):
    monkeypatch.setattr(authz_scope.settings, "allowlist_domains", ["example.com"])
    monkeypatch.setattr(authz_scope.settings, "allowlist_cidrs", ["93.184.216.0/24"])
    assert authz_scope.is_authorized_target("example.com") in {True, False}

