import pytest
from domradar import (
    _is_valid_domain,
    _normalize_domain,
    format_rdap,
    generate_similar,
    guess_availability_from_text,
    split_domain,
)


class TestNormalizeDomain:
    def test_strips_https(self):
        assert _normalize_domain("https://example.com") == "example.com"

    def test_strips_http(self):
        assert _normalize_domain("http://example.com") == "example.com"

    def test_strips_trailing_slash(self):
        assert _normalize_domain("https://example.com/") == "example.com"

    def test_lowercases(self):
        assert _normalize_domain("Example.COM") == "example.com"

    def test_plain_domain_unchanged(self):
        assert _normalize_domain("example.com") == "example.com"


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
        assert guess_availability_from_text("Domain Name: EXAMPLE.COM\nRegistrar: Example Inc") is False
        assert guess_availability_from_text("Creation Date: 2020-01-01") is False
        assert guess_availability_from_text("Status: ok") is False
        assert guess_availability_from_text("Registry Domain ID: 12345") is False

    def test_unknown_returns_none(self):
        assert guess_availability_from_text("% some unrecognized WHOIS response") is None


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
