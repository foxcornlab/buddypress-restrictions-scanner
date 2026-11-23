"""Tests for buddypress_restrictions_scanner.py.

Everything runs against local fixtures: synthetic plugin trees,
a mock WordPress site on localhost, and synthetic access logs. No
real WordPress site is touched, and no payload is ever sent.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import buddypress_restrictions_scanner as scanner

# ---------------------------------------------------------------- version

GRADE_CASES = [
    # (version string, expected verdict)
    ("1.5.4", "VULNERABLE"),   # last vulnerable release, one patch behind
    ("1.5.3", "VULNERABLE"),
    ("1.5.0", "VULNERABLE"),
    ("1.0.0", "VULNERABLE"),   # NVD range starts at 0
    ("1.5", "VULNERABLE"),     # bare 1.5 == 1.5.0
    ("1", "VULNERABLE"),
    ("1.5.5", "FIXED"),        # first fixed release, shipped 12 Nov 2026
    ("1.5.6", "FIXED"),
    ("1.6.0", "FIXED"),
    ("2.0.0", "FIXED"),
    ("banana", "UNKNOWN"),
    ("", "UNKNOWN"),
]


@pytest.mark.parametrize("raw,expected", GRADE_CASES)
def test_grade_versions(raw, expected):
    verdict, _detail = scanner.grade(scanner.parse_version(raw))
    assert verdict == expected, raw


def test_grade_none_is_unknown():
    assert scanner.grade(None)[0] == "UNKNOWN"


def test_parse_version_tolerates_suffixes():
    assert scanner.parse_version("1.5.4.1") == (1, 5, 4)
    assert scanner.parse_version("1.5.5-beta1") == (1, 5, 5)
    assert scanner.parse_version("v1.5.4") == (1, 5, 4)


def test_1_5_4_trap_names_it_last_vulnerable():
    _verdict, detail = scanner.grade(scanner.parse_version("1.5.4"))
    assert "last vulnerable" in detail


def test_fixed_detail_names_the_early_fix_date():
    _verdict, detail = scanner.grade(scanner.parse_version("1.5.5"))
    assert "2026-11-12" in detail  # fix shipped nine days before the CVE


def test_no_buddypress_is_not_exposed():
    verdict, detail = scanner.grade(
        scanner.parse_version("1.5.4"), buddypress=False)
    assert verdict == "NOT_EXPOSED"
    assert "BuddyPress" in detail


def test_no_pmpro_is_not_exposed():
    verdict, detail = scanner.grade(
        scanner.parse_version("1.5.4"), pmpro=False)
    assert verdict == "NOT_EXPOSED"
    assert "Paid Memberships Pro" in detail


def test_no_both_companions_is_not_exposed():
    verdict, _detail = scanner.grade(
        scanner.parse_version("1.5.4"), buddypress=False, pmpro=False)
    assert verdict == "NOT_EXPOSED"


def test_fixed_stays_fixed_without_companions():
    verdict, _detail = scanner.grade(
        scanner.parse_version("1.5.5"), buddypress=False, pmpro=False)
    assert verdict == "FIXED"


# ------------------------------------------------------- version extraction

SAMPLE_HEADER = """<?php
/**
 *  Restrictions for BuddyPress
 *
 * @wordpress-plugin
 * Plugin Name:       BP Restrict
 * Version:           1.5.4
 * Author:            SeventhQueen
 */
"""


def test_header_version_extraction():
    assert scanner.extract_plugin_header_version(SAMPLE_HEADER) == (1, 5, 4)


def test_header_version_missing_is_none():
    assert scanner.extract_plugin_header_version("<?php\n// nothing\n") is None


SAMPLE_README = """=== Restrictions for BuddyPress ===
Contributors: seventhqueen
Requires at least: 5.0
Tested up to: 7.1.4
Stable tag: 1.5.4
Requires PHP: 7.4
"""


def test_stable_tag_extraction():
    assert scanner.extract_stable_tag(SAMPLE_README) == (1, 5, 4)


def test_stable_tag_missing_is_none():
    assert scanner.extract_stable_tag("no tag here\n") is None


# ------------------------------------------------------------------- local

def _plugin_tree(tmp_path, version, buddypress=True, pmpro=True):
    plugins = tmp_path / "plugins"
    bp = plugins / "bp-restrict"
    bp.mkdir(parents=True)
    (bp / "bp-restrict.php").write_text(
        SAMPLE_HEADER.replace("1.5.4", version))
    (bp / "readme.txt").write_text(
        SAMPLE_README.replace("1.5.4", version))
    if buddypress:
        buddy = plugins / "buddypress"
        buddy.mkdir()
        (buddy / "buddypress.php").write_text("<?php\n/* Version: 14.0 */\n")
    if pmpro:
        pro = plugins / "paid-memberships-pro"
        pro.mkdir()
        (pro / "paid-memberships-pro.php").write_text(
            "<?php\n/* Version: 3.5 */\n")
    return plugins


def test_local_vulnerable_tree(tmp_path):
    plugins = _plugin_tree(tmp_path, "1.5.4")
    version, buddy, pro, _notes = scanner.read_local_plugin_version(plugins)
    assert version == (1, 5, 4)
    assert buddy and pro
    assert scanner.grade(version, buddy, pro)[0] == "VULNERABLE"


def test_local_fixed_tree(tmp_path):
    plugins = _plugin_tree(tmp_path, "1.5.5")
    version, buddy, pro, _notes = scanner.read_local_plugin_version(plugins)
    assert scanner.grade(version, buddy, pro)[0] == "FIXED"


def test_local_missing_pmpro_is_not_exposed(tmp_path):
    plugins = _plugin_tree(tmp_path, "1.5.4", pmpro=False)
    version, buddy, pro, notes = scanner.read_local_plugin_version(plugins)
    assert not pro
    assert scanner.grade(version, buddy, pro)[0] == "NOT_EXPOSED"
    assert any("Paid Memberships Pro" in n for n in notes)


def test_local_missing_buddypress_is_not_exposed(tmp_path):
    plugins = _plugin_tree(tmp_path, "1.5.4", buddypress=False)
    version, buddy, pro, _notes = scanner.read_local_plugin_version(plugins)
    assert scanner.grade(version, buddy, pro)[0] == "NOT_EXPOSED"


def test_local_wrong_directory_is_unknown(tmp_path):
    # the slug trap: restrictions-for-buddypress is not the dir name
    wrong = tmp_path / "plugins" / "restrictions-for-buddypress"
    wrong.mkdir(parents=True)
    (wrong / "bp-restrict.php").write_text(SAMPLE_HEADER)
    version, _b, _p, notes = scanner.read_local_plugin_version(
        tmp_path / "plugins")
    assert version is None
    assert any("bp-restrict" in n for n in notes)


def test_local_missing_plugin_is_unknown(tmp_path):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    version, _b, _p, _notes = scanner.read_local_plugin_version(plugins)
    assert version is None


# --------------------------------------------------------------------- url

def _mock_site(routes):
    """A localhost server answering from a {path: (status, body)} map."""
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = routes.get(self.path, (404, "not found"))
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def test_url_vulnerable_readme(tmp_path):
    routes = {
        "/wp-content/plugins/bp-restrict/readme.txt": (
            200, SAMPLE_README),
    }
    server, base = _mock_site(routes)
    try:
        version, _notes = scanner.probe_url(base)
        assert version == (1, 5, 4)
        assert scanner.grade(version)[0] == "VULNERABLE"
    finally:
        server.shutdown()


def test_url_fixed_readme():
    routes = {
        "/wp-content/plugins/bp-restrict/readme.txt": (
            200, SAMPLE_README.replace("1.5.4", "1.5.5")),
    }
    server, base = _mock_site(routes)
    try:
        version, _notes = scanner.probe_url(base)
        assert scanner.grade(version)[0] == "FIXED"
    finally:
        server.shutdown()


def test_url_readme_404_is_unknown():
    server, base = _mock_site({})
    try:
        version, notes = scanner.probe_url(base)
        assert version is None
        assert scanner.grade(version)[0] == "UNKNOWN"
        assert any("404" in n for n in notes)
    finally:
        server.shutdown()


def test_url_readme_uppercase_fallback():
    routes = {
        "/wp-content/plugins/bp-restrict/readme.txt": (404, "nope"),
        "/wp-content/plugins/bp-restrict/README.txt": (
            200, SAMPLE_README),
    }
    server, base = _mock_site(routes)
    try:
        version, _notes = scanner.probe_url(base)
        assert version == (1, 5, 4)
    finally:
        server.shutdown()


def test_url_companion_hint_does_not_flip_verdict():
    # buddypress + pmpro readmes 404: the verdict stays VULNERABLE,
    # the notes say to confirm locally.
    routes = {
        "/wp-content/plugins/bp-restrict/readme.txt": (
            200, SAMPLE_README),
    }
    server, base = _mock_site(routes)
    try:
        version, notes = scanner.probe_url(base)
        assert scanner.grade(version)[0] == "VULNERABLE"
        assert any("BuddyPress" in n for n in notes)
    finally:
        server.shutdown()


# -------------------------------------------------------------- access log

def test_access_log_finds_exploit_uri(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '10.0.0.1 - - [21/Nov/2026:06:00:00 +0000] "GET /members/ HTTP/1.1" 200 1234\n'
        '10.0.0.2 - - [21/Nov/2026:06:01:00 +0000] "GET /{${phpinfo()}} HTTP/1.1" 200 5678\n'
        '10.0.0.3 - - [21/Nov/2026:06:02:00 +0000] "GET /groups/ HTTP/1.1" 200 999\n')
    hits, _notes = scanner.scan_access_log(log)
    assert len(hits) == 1
    assert hits[0][1] == 2
    assert "{${" in hits[0][2]


def test_access_log_clean_is_empty(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(
        '10.0.0.1 - - [21/Nov/2026:06:00:00 +0000] "GET /members/ HTTP/1.1" 200 1234\n')
    hits, _notes = scanner.scan_access_log(log)
    assert hits == []


def test_access_log_missing_path(tmp_path):
    hits, notes = scanner.scan_access_log(tmp_path / "nope.log")
    assert hits == []
    assert notes


# --------------------------------------------------------------- inventory

def test_inventory_mixed_verdicts(tmp_path):
    plugins = _plugin_tree(tmp_path, "1.5.4")
    entries = [
        {"host": "vuln-site", "version": "1.5.4"},
        {"host": "fixed-site", "version": "1.5.5"},
        {"host": "local-site", "plugins_dir": str(plugins)},
        {"host": "no-pmpro", "version": "1.5.4", "pmpro": False},
    ]
    results = [scanner.grade_one(e) for e in entries]
    assert [r["verdict"] for r in results] == [
        "VULNERABLE", "FIXED", "VULNERABLE", "NOT_EXPOSED"]
    assert scanner.worst_verdict(results) == "VULNERABLE"


def test_inventory_unknown_entry(tmp_path):
    results = [scanner.grade_one({"host": "empty"})]
    assert results[0]["verdict"] == "UNKNOWN"


# --------------------------------------------------------------------- cli

def test_cli_version_vulnerable(capsys):
    assert scanner.main(["--version", "1.5.4"]) == scanner.EXIT_VULNERABLE
    assert "VULNERABLE" in capsys.readouterr().out


def test_cli_version_fixed(capsys):
    assert scanner.main(["--version", "1.5.5"]) == scanner.EXIT_CLEAN
    assert "FIXED" in capsys.readouterr().out


def test_cli_version_unknown(capsys):
    assert scanner.main(["--version", "banana"]) == scanner.EXIT_UNKNOWN


def test_cli_no_buddypress_flag(capsys):
    assert scanner.main(
        ["--version", "1.5.4", "--no-buddypress"]) == scanner.EXIT_CLEAN
    assert "NOT_EXPOSED" in capsys.readouterr().out


def test_cli_list(capsys):
    assert scanner.main(["--list"]) == scanner.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "1.5.5" in out
    assert "1.5.4" in out


def test_cli_inventory_json(tmp_path, capsys):
    inv = tmp_path / "fleet.json"
    inv.write_text(json.dumps([
        {"host": "a", "version": "1.5.4"},
        {"host": "b", "version": "1.5.5"},
    ]))
    assert scanner.main(["--inventory-json", str(inv)]) == \
        scanner.EXIT_VULNERABLE
    out = capsys.readouterr().out
    assert "VULNERABLE" in out and "FIXED" in out


def test_cli_wp_root(tmp_path, capsys):
    wp = tmp_path / "wordpress"
    plugins = _plugin_tree(wp / "wp-content", "1.5.4")
    assert scanner.main(["--wp-root", str(wp)]) == scanner.EXIT_VULNERABLE
    assert "VULNERABLE" in capsys.readouterr().out
