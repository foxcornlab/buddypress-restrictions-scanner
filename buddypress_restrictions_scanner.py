#!/usr/bin/env python3
"""Detection-only triage for Restrictions for BuddyPress CVE-2026-120539.

Unauthenticated remote code execution in the Restrictions for
BuddyPress WordPress plugin (seventhqueen), all versions up to and
including 1.5.4. The plugin splices the attacker-controlled request
URI into a PHP expression inside a double-quoted string and evaluates
it with eval(). Because PHP interpolates double-quoted strings, a
payload of the form {${...}} in the URL path is executed during
interpolation itself, so no quote breakout is required and WordPress'
slashing does not mitigate it. An unauthenticated attacker gets
arbitrary PHP code execution on the server with a single GET request.
CVSS 3.1 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-95
(eval injection). CNA: Wordfence.

The affected conditions ship enabled by default and are evaluated
before any logged-in check, so no plugin configuration is needed —
but the site must have BuddyPress AND Paid Memberships Pro active
alongside this plugin. Without either one, the vulnerable code path
never runs and the site is not exposed to this CVE.

Detection only. This scanner never sends a payload, never requests
a crafted URI, and never touches eval(). What it does instead is
version-table grading against the vendor's fixed release, plus
reading the version your site already discloses. The only thing it
asks a remote site for is a plain GET of the plugin's readme.txt
(the file WordPress ships with the installed plugin, which carries
the installed version as its Stable tag). A public exploit (LLCForge,
21 Nov 2026) exists; this tool is the defensive counterpart.

Fixed release, per the vendor (primary source — GitHub release 1.5.5
of seventhqueen/buddypress-restrict, 12 Nov 2026):

    Restrictions for BuddyPress 1.5.4 and earlier -> 1.5.5 (or later)

Note the date: the fix shipped on 12 November, nine days before the
CVE record was published on 21 November. A site that updated any
time after the 12th is already fixed. The CVE record itself is what
most trackers quote, and some of them still list "no fix" — that is
stale. This scanner grades against the vendor release, not the
tracker lag.

There is no workaround. Deactivating the plugin closes the hole;
updating to 1.5.5 closes it properly. And patching alone is not
enough if the site was already hit: this is unauthenticated RCE, so
rotate database passwords and WordPress salts, and hunt your access
logs for `{${` in request URIs (`--access-log` greps for exactly
that pattern).
"""

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

CVE_MAIN = "CVE-2026-120539"
CVSS = "9.8"
CWE = "CWE-95"
VENDOR = "seventhqueen"
PLUGIN_SLUG = "bp-restrict"
PLUGIN_NAME = "Restrictions for BuddyPress"
FIXED_VERSION = (1, 5, 5)
FIXED_LABEL = "1.5.5"
CVE_PUBLISHED = "2026-11-21"
FIX_RELEASED = "2026-11-12"

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3

# The plugin's own directory under wp-content/plugins/. The slug is
# bp-restrict — "restrictions-for-buddypress" is only the wordpress.org
# search URL, not the installed directory. Looking in the wrong
# directory is the easiest way to grade a vulnerable install UNKNOWN.
PLUGIN_DIR = "bp-restrict"
PLUGIN_MAIN_FILE = "bp-restrict.php"
BUDDYPRESS_DIR = "buddypress"
BUDDYPRESS_MAIN_FILE = "buddypress.php"
PMPRO_DIR = "paid-memberships-pro"
PMPRO_MAIN_FILE = "paid-memberships-pro.php"

# A version token: "1.5.4", "1.5.5", "1.5", "1". Extra components
# ("1.5.4.1") and suffixes ("-beta1", "dev") are tolerated and ignored
# past the third component; the numeric prefix is what grades.
VERSION_TOKEN = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

# WordPress plugin header in the main PHP file.
HEADER_VERSION = re.compile(
    r"^\s*\*?\s*Version:\s*([0-9][^\s*]*)\s*$", re.MULTILINE
)
# readme.txt Stable tag, shipped with the installed plugin.
STABLE_TAG = re.compile(
    r"^\s*Stable tag:\s*([0-9][^\s]*)\s*$", re.MULTILINE | re.IGNORECASE
)

# The exploit URI carries a PHP interpolation payload of the form
# {${...}} in the request path. Any access-log line containing it is
# a compromise probe worth investigating — it is not a normal URI.
EXPLOIT_URI_PATTERN = re.compile(r"\{\$\{")

MAX_LOG_BYTES = 50 * 1024 * 1024  # per file, so a giant log cannot OOM us


def parse_version(raw):
    """Parse "1.5.4" (or "1.5", "1", "1.5.4.1") into (1, 5, 4).

    Returns None when the string carries no version token at all.
    Missing components default to 0, so "1.5" means (1, 5, 0).
    """
    if raw is None:
        return None
    match = VERSION_TOKEN.search(str(raw).strip())
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0
    return (major, minor, patch)


def fmt_version(version):
    """Render a version tuple as the plugin writes it: 1.5.4."""
    return "%d.%d.%d" % version


def grade(version, buddypress=True, pmpro=True):
    """Grade a parsed version tuple.

    Returns (verdict, detail) with verdict VULNERABLE, FIXED,
    NOT_EXPOSED or UNKNOWN. `buddypress` / `pmpro` say whether the
    two companion plugins are active: this flaw needs both, so a
    site missing either one is not exposed to this CVE. The default
    assumes both are present, because guessing "absent" would
    under-report the risk — pass --no-buddypress / --no-pmpro, or let
    --local prove it, to grade NOT_EXPOSED.
    """
    if version is None:
        return "UNKNOWN", "no parseable version"

    if version >= FIXED_VERSION:
        return "FIXED", (
            "%s is at or above the fixed release %s (shipped %s, nine "
            "days before the CVE record was published on %s)"
            % (fmt_version(version), FIXED_LABEL, FIX_RELEASED,
               CVE_PUBLISHED)
        )

    detail = (
        "%s is below the fixed release %s; update to %s or later"
        % (fmt_version(version), FIXED_LABEL, FIXED_LABEL)
    )
    if version == (1, 5, 4):
        detail += (
            " — 1.5.4 is the last vulnerable release, one patch behind "
            "the fix; do not mistake 'latest before the CVE' for 'patched'"
        )

    if not buddypress and not pmpro:
        return "NOT_EXPOSED", (
            detail + "; BuddyPress and Paid Memberships Pro are both "
            "absent, and this flaw needs both active, so the site is "
            "not exposed to %s" % CVE_MAIN
        )
    if not buddypress:
        return "NOT_EXPOSED", (
            detail + "; BuddyPress is absent, and this flaw needs "
            "BuddyPress active alongside the plugin, so the site is "
            "not exposed to %s" % CVE_MAIN
        )
    if not pmpro:
        return "NOT_EXPOSED", (
            detail + "; Paid Memberships Pro is absent, and this flaw "
            "needs it active alongside the plugin, so the site is not "
            "exposed to %s" % CVE_MAIN
        )
    return "VULNERABLE", detail + (
        "; unauthenticated RCE via eval() on the request URI, no login "
        "and no configuration needed — patch, then hunt your access "
        "logs for `{${` in request URIs"
    )


def extract_plugin_header_version(text):
    """Read the Version: header out of a plugin's main PHP file."""
    if not text:
        return None
    match = HEADER_VERSION.search(text)
    if not match:
        return None
    return parse_version(match.group(1))


def extract_stable_tag(text):
    """Read the Stable tag: out of a plugin readme.txt."""
    if not text:
        return None
    match = STABLE_TAG.search(text)
    if not match:
        return None
    return parse_version(match.group(1))


def read_local_plugin_version(plugins_dir):
    """Grade from a local wp-content/plugins directory.

    Returns (version tuple or None, buddypress present bool, pmpro
    present bool, notes list). The plugin directory is bp-restrict;
    a wp-content/plugins tree without it grades UNKNOWN, it does not
    guess. Presence of the companion plugins is proven by their main
    PHP files existing in the same tree.
    """
    notes = []
    base = Path(plugins_dir)
    main = base / PLUGIN_DIR / PLUGIN_MAIN_FILE
    if not main.is_file():
        return None, True, True, [
            "no %s/%s found under %s — pass the wp-content/plugins "
            "directory, or --wp-root for a WordPress install"
            % (PLUGIN_DIR, PLUGIN_MAIN_FILE, plugins_dir)
        ]
    try:
        text = main.read_text(errors="replace")
    except OSError as exc:
        return None, True, True, ["cannot read %s: %s" % (main, exc)]
    version = extract_plugin_header_version(text)
    if version is None:
        notes.append(
            "%s has no parseable Version: header" % PLUGIN_MAIN_FILE)
    buddypress = (base / BUDDYPRESS_DIR / BUDDYPRESS_MAIN_FILE).is_file()
    pmpro = (base / PMPRO_DIR / PMPRO_MAIN_FILE).is_file()
    if not buddypress:
        notes.append("BuddyPress not found in this plugins tree")
    if not pmpro:
        notes.append("Paid Memberships Pro not found in this plugins tree")
    return version, buddypress, pmpro, notes


def _unverified_context():
    """WordPress sites often run self-signed certificates; the probe
    only reads a public readme.txt, so verification is skipped the
    way a browser in a lab does it. Never send credentials over this
    channel — this tool never sends any."""
    return ssl._create_unverified_context()


def fetch(url, timeout=10):
    """Plain GET. Returns (status, body, error).

    Status None means the connection itself failed; the error string
    says why. HTTPS uses an unverified context (see above).
    """
    headers = {
        "User-Agent": "buddypress-restrictions-scanner/1.0 "
                      "(detection-only triage)"
    }
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=timeout, context=_unverified_context()
        ) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return exc.code, body, None
    except Exception as exc:  # connection refused, DNS, timeout, TLS
        return None, "", str(exc)


def probe_url(base_url):
    """Grade a live site from its plugin readme.txt.

    One plain GET of /wp-content/plugins/bp-restrict/readme.txt (the
    file WordPress ships with the installed plugin, whose Stable tag
    is the installed version). Falls back to README.txt. No payload,
    no crafted URI, no POST — the request is a file a browser would
    fetch anyway. Returns (version or None, notes list). BuddyPress /
    PMPro presence cannot be proven remotely: their readme.txt files
    are fetched as a hint only, and a 404 there never flips the
    verdict, because many hosts block readme.txt outright.
    """
    notes = []
    base = base_url.rstrip("/")
    version = None
    for name in ("readme.txt", "README.txt"):
        url = "%s/wp-content/plugins/%s/%s" % (base, PLUGIN_DIR, name)
        status, body, error = fetch(url)
        if status is None:
            return None, ["could not reach %s: %s" % (url, error)]
        if status == 200:
            version = extract_stable_tag(body)
            if version is None:
                notes.append(
                    "%s fetched but carries no parseable Stable tag" % name)
            break
        if status in (403, 404):
            notes.append(
                "%s returned HTTP %d — the host may block plugin "
                "readme files; grade locally with --wp-root instead"
                % (name, status))
            continue
        notes.append("%s returned HTTP %d" % (name, status))
    if version is None and not notes:
        notes.append("no readme.txt found for the plugin")
    for companion, label in (
        (BUDDYPRESS_DIR, "BuddyPress"),
        (PMPRO_DIR, "Paid Memberships Pro"),
    ):
        url = "%s/wp-content/plugins/%s/readme.txt" % (base, companion)
        status, _body, _error = fetch(url)
        if status == 200:
            notes.append("%s readme.txt reachable (presence hint)" % label)
        elif status == 404:
            notes.append(
                "%s readme.txt returned 404 — if the plugin is really "
                "absent the site is NOT_EXPOSED, but hosts often block "
                "readme files, so confirm locally and pass "
                "--no-%s if it is truly not installed"
                % (label, companion.replace("-", "")))
    return version, notes


def scan_access_log(path):
    """Grep access logs for the exploit URI pattern `{${`.

    Accepts one log file or a directory of .log files. Returns a list
    of (file, line number, line) hits, capped at 50. A hit is a
    compromise probe worth investigating, not proof of a breach — and
    no hits is not a clean bill, because logs rotate and attackers
    clean up.
    """
    hits = []
    target = Path(path)
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.log"))
    else:
        return hits, ["access log path %s does not exist" % path]
    for logfile in files:
        try:
            size = logfile.stat().st_size
        except OSError:
            continue
        with logfile.open(errors="replace") as handle:
            if size > MAX_LOG_BYTES:
                handle.seek(size - MAX_LOG_BYTES)
                handle.readline()  # drop the partial first line
            for lineno, line in enumerate(handle, start=1):
                if EXPLOIT_URI_PATTERN.search(line):
                    hits.append((str(logfile), lineno, line.rstrip("\n")))
                    if len(hits) >= 50:
                        return hits, ["hit cap reached (50), refine the search"]
    return hits, []


def grade_one(entry):
    """Grade one inventory entry.

    Entry keys: "version" (string), "url" (site base URL), "wp_root"
    (local WordPress root) or "plugins_dir" (local plugins dir).
    Optional: "buddypress" / "pmpro" booleans, "access_log" path.
    Returns a result dict.
    """
    result = {"host": entry.get("host", entry.get("url", "?"))}
    version = None
    buddypress = entry.get("buddypress", True)
    pmpro = entry.get("pmpro", True)
    notes = []
    if "version" in entry:
        version = parse_version(entry["version"])
        if version is None:
            notes.append("version %r is not parseable" % entry["version"])
    elif "url" in entry:
        version, url_notes = probe_url(entry["url"])
        notes.extend(url_notes)
    elif "wp_root" in entry:
        plugins = str(Path(entry["wp_root"]) / "wp-content" / "plugins")
        version, buddypress, pmpro, local_notes = read_local_plugin_version(plugins)
        notes.extend(local_notes)
    elif "plugins_dir" in entry:
        version, buddypress, pmpro, local_notes = read_local_plugin_version(
            entry["plugins_dir"])
        notes.extend(local_notes)
    else:
        return dict(result, verdict="UNKNOWN",
                    detail="entry has no version, url, wp_root or plugins_dir",
                    notes=notes)
    verdict, detail = grade(version, buddypress=buddypress, pmpro=pmpro)
    result["verdict"] = verdict
    result["detail"] = detail
    if version is not None:
        result["version"] = fmt_version(version)
    result["notes"] = notes
    log_path = entry.get("access_log")
    if log_path:
        hits, log_notes = scan_access_log(log_path)
        notes.extend(log_notes)
        result["access_log_hits"] = [
            {"file": f, "line": n, "text": t} for f, n, t in hits
        ]
        if hits:
            result["verdict"] = "VULNERABLE" if verdict == "VULNERABLE" else verdict
            result["detail"] += (
                "; %d access-log line(s) carry the `{${` exploit URI "
                "pattern — investigate, patching alone does not evict "
                "an attacker who already got in" % len(hits))
    return result


def worst_verdict(results):
    """The fleet verdict is the worst of its members."""
    order = {"VULNERABLE": 0, "UNKNOWN": 1, "NOT_EXPOSED": 2, "FIXED": 3}
    return min(results, key=lambda r: order.get(r["verdict"], 1))["verdict"]


def print_result(result, as_json=False):
    """One result, human or machine readable."""
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("[%s] %s" % (result["verdict"], result["host"]))
    if "version" in result:
        print("  version: %s" % result["version"])
    print("  %s" % result["detail"])
    for note in result.get("notes", []):
        print("  note: %s" % note)
    for hit in result.get("access_log_hits", []):
        print("  log hit %s:%s: %s" % (hit["file"], hit["line"], hit["text"]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Restrictions for "
                    "BuddyPress %s (CVSS %s). Grades the installed plugin "
                    "version against the %s fix. Never sends payloads."
                    % (CVE_MAIN, CVSS, FIXED_LABEL))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version", metavar="VERSION",
                       help="grade a version string, e.g. 1.5.4")
    group.add_argument("--version-file", metavar="FILE",
                       help="read the version from a file (first line)")
    group.add_argument("--url", metavar="URL",
                       help="grade a live site from its plugin readme.txt")
    group.add_argument("--wp-root", metavar="DIR",
                       help="grade a local WordPress install directory")
    group.add_argument("--plugins-dir", metavar="DIR",
                       help="grade a local wp-content/plugins directory")
    group.add_argument("--local", metavar="PATH",
                       help="grade a local plugins dir, wp root, plugin "
                            "PHP file or readme.txt")
    group.add_argument("--inventory-json", metavar="FILE",
                       help="grade a fleet from a JSON list of entries")
    group.add_argument("--list", action="store_true",
                       help="print the fixed-version table and exit")
    parser.add_argument("--no-buddypress", action="store_true",
                        help="BuddyPress is not active on this site")
    parser.add_argument("--no-pmpro", action="store_true",
                        help="Paid Memberships Pro is not active on this site")
    parser.add_argument("--access-log", metavar="PATH",
                        help="grep an access log (file or dir of .log) for "
                             "the `{${` exploit URI pattern")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print("%s — %s — %s" % (PLUGIN_NAME, CVE_MAIN, CVSS))
        print("affected: %s 1.5.4 and earlier" % PLUGIN_NAME)
        print("fixed:    %s %s (released %s; CVE published %s)"
              % (PLUGIN_NAME, FIXED_LABEL, FIX_RELEASED, CVE_PUBLISHED))
        print("needs:    BuddyPress AND Paid Memberships Pro active")
        return EXIT_CLEAN

    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("cannot read inventory: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
        if not isinstance(entries, list) or not entries:
            print("inventory must be a non-empty JSON list", file=sys.stderr)
            return EXIT_USAGE
        results = [grade_one(entry) for entry in entries]
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                print_result(result)
        verdict = worst_verdict(results)
        return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
            verdict, EXIT_CLEAN)

    entry = {}
    if args.version is not None:
        entry["version"] = args.version
    elif args.version_file is not None:
        try:
            entry["version"] = Path(args.version_file).read_text().splitlines()[0]
        except (OSError, IndexError) as exc:
            print("cannot read version file: %s" % exc, file=sys.stderr)
            return EXIT_USAGE
    elif args.url is not None:
        entry["url"] = args.url
    elif args.wp_root is not None:
        entry["wp_root"] = args.wp_root
    elif args.plugins_dir is not None:
        entry["plugins_dir"] = args.plugins_dir
    elif args.local is not None:
        target = Path(args.local)
        if target.is_file() and target.suffix == ".php":
            version = extract_plugin_header_version(
                target.read_text(errors="replace"))
            entry["version"] = fmt_version(version) if version else ""
        elif target.is_file() and target.name.lower() in ("readme.txt",):
            version = extract_stable_tag(target.read_text(errors="replace"))
            entry["version"] = fmt_version(version) if version else ""
        elif target.is_dir():
            if (target / PLUGIN_DIR / PLUGIN_MAIN_FILE).is_file():
                entry["plugins_dir"] = str(target)
            elif (target / "wp-content" / "plugins" / PLUGIN_DIR).is_dir():
                entry["wp_root"] = str(target)
            else:
                print("cannot find %s under %s — pass a plugins dir, a "
                      "WordPress root, the plugin PHP file or its "
                      "readme.txt" % (PLUGIN_DIR, args.local),
                      file=sys.stderr)
                return EXIT_USAGE
        else:
            print("no such file or directory: %s" % args.local,
                  file=sys.stderr)
            return EXIT_USAGE
    entry["host"] = entry.get("url") or entry.get("wp_root") or \
        entry.get("plugins_dir") or entry.get("version", "?")
    if args.no_buddypress:
        entry["buddypress"] = False
    if args.no_pmpro:
        entry["pmpro"] = False
    if args.access_log:
        entry["access_log"] = args.access_log

    result = grade_one(entry)
    print_result(result, as_json=args.json)
    return {"VULNERABLE": EXIT_VULNERABLE, "UNKNOWN": EXIT_UNKNOWN}.get(
        result["verdict"], EXIT_CLEAN)


if __name__ == "__main__":
    sys.exit(main())
