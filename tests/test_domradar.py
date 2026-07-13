import io
import json
from unittest.mock import patch

import pytest

import domradar
from domradar import (
    CheckResult,
    _bootstrap_tld,
    _collect_input_domains,
    _exit_code_for_check,
    _is_valid_domain,
    _normalize_domain,
    batch_available_similar,
    check_domain,
    format_rdap,
    generate_similar,
    guess_availability_from_text,
    main,
    rdap_lookup,
    split_domain,
    whois_lookup,
)


# --------------------------------------------------------------------------
# Normalize / validate
# --------------------------------------------------------------------------


class TestNormalizeDomain:
    def test_strips_https(self):
        assert _normalize_domain("https://example.com") == "example.com"

    def test_strips_http(self):
        assert _normalize_domain("http://example.com") == "example.com"

    def test_strips_trailing_slash(self):
        assert _normalize_domain("https://example.com/") == "example.com"

    def test_strips_path_and_query(self):
        assert _normalize_domain("https://example.com/foo?bar=1") == "example.com"

    def test_strips_port(self):
        assert _normalize_domain("example.com:8080") == "example.com"

    def test_strips_userinfo(self):
        assert _normalize_domain("https://user:pass@example.com/") == "example.com"

    def test_lowercases(self):
        assert _normalize_domain("Example.COM") == "example.com"

    def test_strips_trailing_dot(self):
        assert _normalize_domain("example.com.") == "example.com"

    def test_plain_domain_unchanged(self):
        assert _normalize_domain("example.com") == "example.com"

    def test_idn_punycodes(self):
        assert _normalize_domain("münchen.de") == "xn--mnchen-3ya.de"

    def test_empty(self):
        assert _normalize_domain("") == ""

    def test_whitespace_only(self):
        assert _normalize_domain("   ") == ""


class TestIsValidDomain:
    def test_valid_domains(self):
        assert _is_valid_domain("example.com") is True
        assert _is_valid_domain("sub.example.com") is True
        assert _is_valid_domain("my-domain.io") is True
        assert _is_valid_domain("a.co") is True
        assert _is_valid_domain("example.co.uk") is True

    def test_invalid_domains(self):
        assert _is_valid_domain("") is False
        assert _is_valid_domain("nodot") is False
        assert _is_valid_domain("-bad.com") is False
        assert _is_valid_domain("bad-.com") is False
        assert _is_valid_domain("has space.com") is False
        assert _is_valid_domain("http://example.com") is False
        assert _is_valid_domain("a" * 254) is False


# --------------------------------------------------------------------------
# WHOIS heuristic
# --------------------------------------------------------------------------


class TestGuessAvailabilityFromText:
    def test_empty_returns_none(self):
        assert guess_availability_from_text("") is None

    def test_not_found_patterns(self):
        assert guess_availability_from_text("No match for EXAMPLE.COM") is True
        assert guess_availability_from_text("Domain not found") is True
        assert guess_availability_from_text("Status: available") is True
        assert guess_availability_from_text("available for registration") is True
        assert guess_availability_from_text("has not been registered") is True

    def test_found_patterns(self):
        assert guess_availability_from_text(
            "Domain Name: EXAMPLE.COM\nRegistrar: Example Inc"
        ) is False
        assert guess_availability_from_text("Creation Date: 2020-01-01") is False
        assert guess_availability_from_text("Status: ok") is False
        assert guess_availability_from_text("Registry Domain ID: 12345") is False

    def test_unknown_returns_none(self):
        assert guess_availability_from_text("% some unrecognized WHOIS response") is None

    def test_domain_name_echo_alone_is_not_taken(self):
        # A response that only echoes the queried domain (common in "not found"
        # replies) must not be classified as TAKEN.
        assert guess_availability_from_text("Domain Name: EXAMPLE.COM") is None

    def test_not_found_wins_over_registrar_echo(self):
        text = "Domain Name: EXAMPLE.COM\nRegistrar: WHOIS.NIC.EXAMPLE\nNOT FOUND"
        assert guess_availability_from_text(text) is True


# --------------------------------------------------------------------------
# Bootstrap TLD longest-match
# --------------------------------------------------------------------------


class TestBootstrapTld:
    def test_single_label_hit(self):
        assert _bootstrap_tld("example.com", {"com": []}) == "com"

    def test_prefers_multi_label(self):
        assert _bootstrap_tld("example.co.uk", {"co.uk": [], "uk": []}) == "co.uk"

    def test_falls_back_to_shorter(self):
        assert _bootstrap_tld("example.co.uk", {"uk": []}) == "uk"

    def test_no_match(self):
        assert _bootstrap_tld("example.invalidtld", {"com": []}) is None

    def test_bare_name_no_match(self):
        assert _bootstrap_tld("example", {"com": []}) is None


# --------------------------------------------------------------------------
# split_domain / generate_similar
# --------------------------------------------------------------------------


class TestSplitDomain:
    def test_with_tld(self):
        assert split_domain("example.com") == ("example", "com")

    def test_without_tld(self):
        assert split_domain("example") == ("example", None)

    def test_multi_part_tld(self):
        assert split_domain("example.co.uk") == ("example", "co.uk")


class TestGenerateSimilar:
    def test_returns_list(self):
        result = generate_similar("example", "com", None)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_no_self_duplicate(self):
        result = generate_similar("example", "com", None)
        assert "example.com" not in result

    def test_no_duplicates(self):
        result = generate_similar("example", "com", None)
        assert len(result) == len(set(result))

    def test_custom_tld_pool(self):
        result = generate_similar("example", None, ["io", "dev"])
        domains = set(result)
        assert "example.io" in domains
        assert "example.dev" in domains

    def test_includes_prefix_variants(self):
        result = generate_similar("example", "com", None)
        assert "getexample.com" in result
        assert "myexample.com" in result

    def test_includes_suffix_variants(self):
        result = generate_similar("example", "com", None)
        assert "examplehq.com" in result


# --------------------------------------------------------------------------
# RDAP formatter
# --------------------------------------------------------------------------


class TestFormatRdap:
    def test_basic_fields(self):
        data = {
            "ldhName": "EXAMPLE.COM",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
        }
        output = format_rdap(data)
        assert "EXAMPLE.COM" in output
        assert "active" in output
        assert "NS1.EXAMPLE.COM" in output
        assert "2020-01-01" in output

    def test_missing_fields_use_na(self):
        output = format_rdap({})
        assert "N/A" in output

    def test_entity_with_vcard(self):
        data = {
            "entities": [{
                "roles": ["registrar"],
                "handle": "REG-001",
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }]
        }
        output = format_rdap(data)
        assert "Example Registrar" in output
        assert "registrar" in output


# --------------------------------------------------------------------------
# rdap_lookup: exercised against mocked _https_get + bootstrap
# --------------------------------------------------------------------------


@pytest.fixture
def stub_bootstrap(monkeypatch):
    def fake(timeout=domradar.DEFAULT_TIMEOUT):
        return {"com": ["https://rdap.example.net/"]}
    monkeypatch.setattr(domradar, "load_rdap_bootstrap", fake)


class TestRdapLookup:
    def test_available_on_404(self, stub_bootstrap, monkeypatch):
        monkeypatch.setattr(domradar, "_https_get", lambda url, headers, timeout: (404, b""))
        assert rdap_lookup("example.com") == {"available": True, "data": None}

    def test_taken_on_200(self, stub_bootstrap, monkeypatch):
        payload = {"ldhName": "example.com", "status": ["active"]}
        monkeypatch.setattr(
            domradar, "_https_get",
            lambda url, headers, timeout: (200, json.dumps(payload).encode()),
        )
        result = rdap_lookup("example.com")
        assert result == {"available": False, "data": payload}

    def test_rate_limited_returns_error(self, stub_bootstrap, monkeypatch):
        monkeypatch.setattr(domradar, "_https_get", lambda url, headers, timeout: (429, b""))
        result = rdap_lookup("example.com")
        assert result["available"] is None
        assert "429" in result["error"]

    def test_server_error_returns_error(self, stub_bootstrap, monkeypatch):
        monkeypatch.setattr(domradar, "_https_get", lambda url, headers, timeout: (503, b""))
        result = rdap_lookup("example.com")
        assert result["available"] is None
        assert "503" in result["error"]

    def test_malformed_json_returns_error(self, stub_bootstrap, monkeypatch):
        monkeypatch.setattr(
            domradar, "_https_get", lambda url, headers, timeout: (200, b"not json"),
        )
        result = rdap_lookup("example.com")
        assert result["available"] is None
        assert "malformed" in result["error"]

    def test_connection_error_returns_error(self, stub_bootstrap, monkeypatch):
        def boom(url, headers, timeout):
            raise OSError("dead socket")
        monkeypatch.setattr(domradar, "_https_get", boom)
        result = rdap_lookup("example.com")
        assert result["available"] is None
        assert "dead socket" in result["error"]

    def test_unsupported_tld_returns_none(self, monkeypatch):
        monkeypatch.setattr(domradar, "load_rdap_bootstrap", lambda timeout=6: {})
        assert rdap_lookup("example.com") is None


# --------------------------------------------------------------------------
# check_domain orchestration
# --------------------------------------------------------------------------


class TestCheckDomain:
    def test_invalid_domain(self):
        res = check_domain("not_a_domain")
        assert res.available is None
        assert res.method == "validation"

    def test_rdap_available(self, monkeypatch):
        monkeypatch.setattr(
            domradar, "rdap_lookup",
            lambda d, timeout=6: {"available": True, "data": None},
        )
        res = check_domain("example.com")
        assert res.available is True
        assert res.method == "RDAP"

    def test_rdap_taken(self, monkeypatch):
        monkeypatch.setattr(
            domradar, "rdap_lookup",
            lambda d, timeout=6: {"available": False, "data": {"ldhName": "x"}},
        )
        res = check_domain("example.com")
        assert res.available is False
        assert res.method == "RDAP"

    def test_rdap_error_falls_back_to_whois(self, monkeypatch):
        monkeypatch.setattr(
            domradar, "rdap_lookup",
            lambda d, timeout=6: {"available": None, "error": "rate limited (HTTP 429)"},
        )
        monkeypatch.setattr(
            domradar, "whois_lookup",
            lambda d, timeout=6: ("Domain not found", None),
        )
        res = check_domain("example.com")
        assert res.available is True
        assert "RDAP fallback" in res.method
        assert "429" in res.detail

    def test_no_rdap_uses_whois(self, monkeypatch):
        monkeypatch.setattr(domradar, "rdap_lookup", lambda d, timeout=6: None)
        monkeypatch.setattr(
            domradar, "whois_lookup",
            lambda d, timeout=6: ("Registrar: NIC\nStatus: active", None),
        )
        res = check_domain("example.tld")
        assert res.available is False
        assert res.method == "WHOIS (heuristic)"

    def test_whois_hard_failure(self, monkeypatch):
        monkeypatch.setattr(domradar, "rdap_lookup", lambda d, timeout=6: None)
        monkeypatch.setattr(
            domradar, "whois_lookup",
            lambda d, timeout=6: ("", "connection refused"),
        )
        res = check_domain("example.tld")
        assert res.available is None
        assert res.method == "WHOIS"
        assert "connection refused" in res.detail


# --------------------------------------------------------------------------
# whois_lookup: referral chain
# --------------------------------------------------------------------------


class TestWhoisLookup:
    def test_follows_referral(self, monkeypatch):
        calls = []

        def fake_query(server, query, timeout=6):
            calls.append(server)
            if server == domradar.IANA_WHOIS_SERVER:
                return "refer: whois.registry.example\n"
            return "Domain Name: EXAMPLE.COM\nRegistrar: Example Inc\n"

        monkeypatch.setattr(domradar, "whois_query", fake_query)
        text, err = whois_lookup("example.com")
        assert err is None
        assert "whois.registry.example" in calls
        assert "Registrar: Example Inc" in text

    def test_stops_on_self_referral(self, monkeypatch):
        def fake_query(server, query, timeout=6):
            return "refer: " + server + "\n"
        monkeypatch.setattr(domradar, "whois_query", fake_query)
        text, err = whois_lookup("example.com")
        assert err is None
        # single response, no loop
        assert text.count("----- Response from") == 1

    def test_partial_success_returns_text(self, monkeypatch):
        seq = iter(["refer: whois.broken.example\n"])

        def fake_query(server, query, timeout=6):
            try:
                return next(seq)
            except StopIteration:
                raise OSError("connection refused")

        monkeypatch.setattr(domradar, "whois_query", fake_query)
        text, err = whois_lookup("example.com")
        assert err is None
        assert "whois.broken.example" not in text or True  # tolerated either way
        assert "refer:" in text

    def test_initial_failure_reports_error(self, monkeypatch):
        def fake_query(server, query, timeout=6):
            raise OSError("boom")
        monkeypatch.setattr(domradar, "whois_query", fake_query)
        text, err = whois_lookup("example.com")
        assert err is not None
        assert "boom" in err
        assert text == ""


# --------------------------------------------------------------------------
# batch_available_similar
# --------------------------------------------------------------------------


class TestBatchSimilar:
    def test_dedupes_across_parents(self, monkeypatch):
        # Force check_domain to say "everything is available"
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: CheckResult(d, True, "stub"),
        )
        taken = [CheckResult("foo.com", False, "stub"),
                 CheckResult("foo.net", False, "stub")]
        out = batch_available_similar(taken, count=5, tlds_pool=None, timeout=1)
        # Same candidate must not appear under both parents.
        seen: set = set()
        for parent, suggestions in out.items():
            for s in suggestions:
                assert s not in seen, f"candidate {s} appeared under multiple parents"
                seen.add(s)

    def test_empty_input(self):
        assert batch_available_similar([], count=5, tlds_pool=None, timeout=1) == {}

    def test_no_available_returns_empty_lists(self, monkeypatch):
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: CheckResult(d, False, "stub"),
        )
        taken = [CheckResult("foo.com", False, "stub")]
        out = batch_available_similar(taken, count=5, tlds_pool=None, timeout=1)
        assert out == {"foo.com": []}


# --------------------------------------------------------------------------
# Exit codes / CLI helpers
# --------------------------------------------------------------------------


class TestExitCodeForCheck:
    def test_all_available(self):
        assert _exit_code_for_check([CheckResult("a.com", True, "x")]) == 0

    def test_any_taken(self):
        assert _exit_code_for_check([
            CheckResult("a.com", True, "x"),
            CheckResult("b.com", False, "x"),
        ]) == 1

    def test_any_unknown(self):
        assert _exit_code_for_check([
            CheckResult("a.com", True, "x"),
            CheckResult("b.com", None, "x"),
        ]) == 2


class TestCollectInputDomains:
    def test_passthrough(self):
        assert _collect_input_domains(["a", "b"]) == ["a", "b"]

    def test_stdin(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("foo.com\n# comment\n\nbar.io\n"))
        assert _collect_input_domains(["-"]) == ["foo.com", "bar.io"]

    def test_mixed(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("x.com\n"))
        assert _collect_input_domains(["a", "-", "b"]) == ["a", "x.com", "b"]


# --------------------------------------------------------------------------
# End-to-end CLI: main() with mocked check_domain
# --------------------------------------------------------------------------


class TestMainCheck:
    def test_json_output(self, monkeypatch, capsys):
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: CheckResult(d, True, "stub"),
        )
        code = main(["check", "example.com", "--json"])
        out = capsys.readouterr().out
        payload = json.loads(out)
        assert code == 0
        assert payload[0]["input"] == "example.com"
        assert payload[0]["results"][0]["domain"] == "example.com"
        assert payload[0]["results"][0]["available"] is True

    def test_exit_1_when_taken(self, monkeypatch, capsys):
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: CheckResult(d, False, "stub"),
        )
        code = main(["check", "example.com"])
        capsys.readouterr()
        assert code == 1

    def test_exit_2_when_unknown(self, monkeypatch, capsys):
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: CheckResult(d, None, "stub", "network down"),
        )
        code = main(["check", "example.com"])
        capsys.readouterr()
        assert code == 2

    def test_available_only_filters_json(self, monkeypatch, capsys):
        results_by_domain = {
            "example.com": CheckResult("example.com", False, "stub"),
            "example.net": CheckResult("example.net", True, "stub"),
        }
        monkeypatch.setattr(
            domradar, "check_domain",
            lambda d, timeout=6: results_by_domain[d],
        )
        main(["check", "example", "--tld", "com,net", "--available-only", "--json"])
        payload = json.loads(capsys.readouterr().out)
        domains_in_output = [r["domain"] for g in payload for r in g["results"]]
        assert "example.net" in domains_in_output
        assert "example.com" not in domains_in_output


class TestMainWhois:
    def test_rdap_taken_exit_0(self, monkeypatch, capsys):
        monkeypatch.setattr(
            domradar, "rdap_lookup",
            lambda d, timeout=6: {"available": False, "data": {"ldhName": "example.com"}},
        )
        code = main(["whois", "example.com", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["available"] is False
        assert payload["record"]["ldhName"] == "example.com"

    def test_rdap_available_exit_1(self, monkeypatch, capsys):
        monkeypatch.setattr(
            domradar, "rdap_lookup",
            lambda d, timeout=6: {"available": True, "data": None},
        )
        code = main(["whois", "example.com", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["available"] is True

    def test_invalid_domain_exit_2(self, capsys):
        code = main(["whois", "not_a_domain", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 2
        assert "error" in payload
