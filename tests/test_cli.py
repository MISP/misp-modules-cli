"""Baseline pytest suite for bin/cli.py.

Covers the pure helper functions: attribute-type detection, markdown table
rendering, and cache key / TTL logic. This suite targets the unmodified
code at the base commit and makes no assumption that any other finding has
been fixed.
"""

import importlib
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

cli = importlib.import_module("bin.cli")


# ---------------------------------------------------------------------------
# Type-detection helpers
# ---------------------------------------------------------------------------


def test_is_ipv4():
    assert cli.is_ipv4("8.8.8.8") is True
    assert cli.is_ipv4("::1") is False
    assert cli.is_ipv4("not-an-ip") is False


def test_is_ipv6():
    assert cli.is_ipv6("::1") is True
    assert cli.is_ipv6("8.8.8.8") is False


def test_looks_like_domain():
    assert cli.looks_like_domain("example.com") is True
    assert cli.looks_like_domain("sub.example.com") is True
    assert cli.looks_like_domain("not a domain") is False
    assert cli.looks_like_domain("nodots") is False
    assert cli.looks_like_domain("-bad.com") is False


def test_looks_like_url():
    assert cli.looks_like_url("https://example.com/path") is True
    assert cli.looks_like_url("ftp://example.com") is True
    assert cli.looks_like_url("example.com") is False


def test_looks_like_email():
    assert cli.looks_like_email("user@example.com") is True
    assert cli.looks_like_email("not-an-email") is False


def test_looks_like_asn():
    assert cli.looks_like_asn("AS1234") is True
    assert cli.looks_like_asn("1234") is True
    assert cli.looks_like_asn("abc") is False


def test_looks_like_cve():
    assert cli.looks_like_cve("CVE-2024-12345") is True
    assert cli.looks_like_cve("cve-2024-1234") is True
    assert cli.looks_like_cve("not-a-cve") is False


def test_looks_like_uuid():
    assert cli.looks_like_uuid("550e8400-e29b-41d4-a716-446655440000") is True
    assert cli.looks_like_uuid("not-a-uuid") is False


def test_hash_detectors():
    assert cli.looks_like_md5("a" * 32) is True
    assert cli.looks_like_md5("a" * 31) is False
    assert cli.looks_like_sha1("a" * 40) is True
    assert cli.looks_like_sha256("a" * 64) is True
    assert cli.looks_like_sha512("a" * 128) is True


def test_looks_like_filename_hash():
    ok, types = cli.looks_like_filename_hash("evil.exe|" + "a" * 32)
    assert ok is True
    assert "filename|md5" in types

    ok, types = cli.looks_like_filename_hash("no-pipe-here")
    assert ok is False
    assert types == []


def test_looks_like_domain_ip():
    assert cli.looks_like_domain_ip("example.com|8.8.8.8") is True
    assert cli.looks_like_domain_ip("example.com|not-an-ip") is False
    assert cli.looks_like_domain_ip("no-pipe") is False


def test_guess_attribute_types_ranks_supported_first():
    valid_types = {"ip-src", "ip-dst", "domain"}
    supported = {"ip-dst"}
    guesses = cli.guess_attribute_types("8.8.8.8", valid_types, supported)
    guessed_types = [t for t, _reason in guesses]
    assert "ip-src" in guessed_types
    assert "ip-dst" in guessed_types
    # supported types are ranked ahead of unsupported ones
    assert guessed_types.index("ip-dst") < guessed_types.index("ip-src")


def test_guess_attribute_types_exact_match_wins():
    valid_types = {"domain"}
    guesses = cli.guess_attribute_types("domain", valid_types, set())
    assert guesses[0][0] == "domain"


# ---------------------------------------------------------------------------
# Module / type mapping helpers
# ---------------------------------------------------------------------------


SAMPLE_MODULES = [
    {
        "name": "module-a",
        "type": "expansion",
        "mispattributes": {"input": ["ip-src", "ip-dst"]},
    },
    {
        "name": "module-b",
        "type": "expansion",
        "mispattributes": {"input": ["domain"]},
    },
    {
        "name": "not-expansion",
        "type": "action",
        "mispattributes": {"input": ["domain"]},
    },
]


def test_get_expansion_modules():
    result = cli.get_expansion_modules(SAMPLE_MODULES)
    names = {m["name"] for m in result}
    assert names == {"module-a", "module-b"}


def test_get_supported_input_types():
    result = cli.get_supported_input_types(SAMPLE_MODULES)
    assert result == {"ip-src", "ip-dst", "domain"}


def test_get_type_to_modules_map():
    result = cli.get_type_to_modules_map(SAMPLE_MODULES)
    assert result["ip-src"] == ["module-a"]
    assert result["domain"] == ["module-b"]


def test_find_modules_for_type():
    result = cli.find_modules_for_type(SAMPLE_MODULES, "domain")
    assert [m["name"] for m in result] == ["module-b"]


# ---------------------------------------------------------------------------
# Markdown table rendering
# ---------------------------------------------------------------------------


def test_format_markdown_output_empty_records():
    output = cli.format_markdown_output("1.2.3.4", None, False, [], [])
    assert "# MISP Modules Query Report" in output
    assert "_No module query records were generated._" in output


def test_format_markdown_output_with_records():
    records = [
        {
            "module": "module-a",
            "attribute_type": "ip-src",
            "status": "success",
            "reason": "matches IPv4 syntax",
            "queried_at": "2026-01-01T00:00:00Z",
            "cache": "miss",
            "query_parameters": {"module": "module-a", "ip-src": "1.2.3.4"},
            "response": {"Category": ["Network activity"]},
        }
    ]
    output = cli.format_markdown_output("1.2.3.4", None, False, [], records)
    assert "Module `module-a`" in output
    assert "Successful queries: `1`" in output
    assert "Failed queries: `0`" in output
    assert "| Key | Value |" in output


def test_response_to_table_via_public_output_list_and_scalar():
    # Exercise list- and scalar-shaped responses indirectly through the
    # public format_markdown_output entry point.
    records = [
        {
            "module": "module-a",
            "attribute_type": "domain",
            "status": "error",
            "reason": "n/a",
            "queried_at": "2026-01-01T00:00:00Z",
            "cache": "n/a",
            "query_parameters": {},
            "response": ["one", "two"],
        }
    ]
    output = cli.format_markdown_output("example.com", "domain", True, ["module-a"], records)
    assert "| Index | Value |" in output
    assert "`0`" in output


# ---------------------------------------------------------------------------
# Cache key / TTL logic
# ---------------------------------------------------------------------------


def test_make_cache_key_is_stable_and_order_independent():
    key1 = cli.make_cache_key("http://x/", "mod", "ip-src", "1.2.3.4", {"a": "1", "b": "2"})
    key2 = cli.make_cache_key("http://x", "mod", "ip-src", "1.2.3.4", {"b": "2", "a": "1"})
    assert key1 == key2


def test_make_cache_key_changes_with_inputs():
    base = cli.make_cache_key("http://x", "mod", "ip-src", "1.2.3.4", {})
    other = cli.make_cache_key("http://x", "mod", "ip-src", "5.6.7.8", {})
    assert base != other


def test_get_cached_response_hit_and_miss():
    cache = {"entries": {}}
    key = "some-key"
    cli.set_cached_response(cache, key, {"foo": "bar"}, now=1000)

    hit = cli.get_cached_response(cache, key, now=1000, ttl_seconds=100)
    assert hit is not None
    assert hit["response"] == {"foo": "bar"}

    miss = cli.get_cached_response(cache, "missing-key", now=1000, ttl_seconds=100)
    assert miss is None


def test_get_cached_response_respects_ttl():
    cache = {"entries": {}}
    key = "some-key"
    cli.set_cached_response(cache, key, {"foo": "bar"}, now=1000)

    still_fresh = cli.get_cached_response(cache, key, now=1099, ttl_seconds=100)
    assert still_fresh is not None

    expired = cli.get_cached_response(cache, key, now=1101, ttl_seconds=100)
    assert expired is None


def test_get_cached_response_handles_malformed_entries():
    cache = {"entries": {"bad": "not-a-dict"}}
    assert cli.get_cached_response(cache, "bad", now=1, ttl_seconds=100) is None
    assert cli.get_cached_response({}, "missing", now=1, ttl_seconds=100) is None


def test_set_cached_response_repairs_non_dict_entries():
    cache = {"entries": "oops"}
    cli.set_cached_response(cache, "key", {"a": 1}, now=5)
    assert cache["entries"]["key"]["response"] == {"a": 1}


# ---------------------------------------------------------------------------
# Misc pure helpers
# ---------------------------------------------------------------------------


def test_is_empty_module_response():
    assert cli.is_empty_module_response(None) is True
    assert cli.is_empty_module_response([]) is True
    assert cli.is_empty_module_response({}) is True
    assert cli.is_empty_module_response({"results": []}) is True
    assert cli.is_empty_module_response({"results": [1]}) is False
    assert cli.is_empty_module_response([1, 2]) is False


def test_redact_config_keys():
    value = {"module": "x", "config": {"apikey": "secret"}, "nested": {"config": "y"}}
    redacted = cli.redact_config_keys(value)
    assert "config" not in redacted
    assert "config" not in redacted["nested"]


def test_uses_misp_standard_format():
    assert cli.uses_misp_standard_format({"mispattributes": {"format": "misp_standard"}}) is True
    assert cli.uses_misp_standard_format({"mispattributes": {"format": "MISP_Standard"}}) is True
    assert cli.uses_misp_standard_format({"mispattributes": {}}) is False


def test_build_payload_standard_and_legacy():
    standard_module = {"mispattributes": {"format": "misp_standard"}}
    payload = cli.build_payload(standard_module, "mod", "ip-src", "1.2.3.4")
    assert payload["attribute"]["type"] == "ip-src"
    assert payload["attribute"]["value"] == "1.2.3.4"

    legacy_module = {"mispattributes": {}}
    payload = cli.build_payload(legacy_module, "mod", "ip-src", "1.2.3.4")
    assert payload == {"module": "mod", "ip-src": "1.2.3.4"}
