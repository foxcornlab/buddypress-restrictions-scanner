# `buddypress-restrictions-scanner`

Detection-only triage for `CVE-2026-120539`, the unauthenticated remote code execution in `Restrictions for BuddyPress` (`seventhqueen`) that `Wordfence` published on `2026-11-21` — and that already had public exploit code the same morning (`LLCForge`, `08:12 UTC`). Grades your installed plugin version against the fixed release, fingerprints a live site from the version it already discloses, and hunts your access logs for the exploit URI pattern. Nothing here sends a payload, requests a crafted URI, or touches `eval()`.

## `What it checks`

* `CVE-2026-120539` — the `Restrictions for BuddyPress` plugin splices the attacker-controlled request URI into a `PHP` expression inside a double-quoted string and evaluates it with `eval()`. Because `PHP` interpolates double-quoted strings, a payload of the form `{${...}}` in the URL path executes during interpolation itself — no quote breakout required, and `WordPress` slashing does not mitigate it. One unauthenticated `GET` request, arbitrary `PHP` on the server. `CVSS 3.1 9.8` (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), `CWE-95` (eval injection). The affected conditions ship enabled by default and are evaluated before any logged-in check, so no configuration is needed — but the site must have `BuddyPress` and `Paid Memberships Pro` active alongside the plugin. Without either one, the vulnerable code never runs.

Fixed version, per the vendor (primary source):

| `Build` | `Upgrade to` |
| --- | --- |
| `Restrictions for BuddyPress 1.5.4` and earlier | `1.5.5` (or later) |

There is no workaround. Deactivate the plugin or update to `1.5.5`.

## `Usage`

```bash
# grade a version string
python3 buddypress_restrictions_scanner.py --version "1.5.4"
python3 buddypress_restrictions_scanner.py --version "1.5.5"

# a live site: one plain GET of the plugin readme.txt, nothing else
python3 buddypress_restrictions_scanner.py --url https://example.com

# on the box itself (a WordPress install or a plugins directory)
python3 buddypress_restrictions_scanner.py --wp-root /var/www/html
python3 buddypress_restrictions_scanner.py --plugins-dir /var/www/html/wp-content/plugins

# a site that does not run BuddyPress or Paid Memberships Pro
python3 buddypress_restrictions_scanner.py --version "1.5.4" --no-pmpro

# hunt the access logs for the exploit URI pattern
python3 buddypress_restrictions_scanner.py --version "1.5.4" --access-log /var/log/apache2/access.log

# a whole fleet at once
python3 buddypress_restrictions_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 buddypress_restrictions_scanner.py --version "1.5.4" --json
python3 buddypress_restrictions_scanner.py --list
```

`--url` `GET`s `/wp-content/plugins/bp-restrict/readme.txt` and reads the installed version out of its `Stable tag` — the file `WordPress` ships with the installed plugin. It also fetches the `BuddyPress` and `Paid Memberships Pro` readme files as a presence hint, but a `404` there never flips the verdict, because many hosts block readme files outright. `--wp-root` / `--plugins-dir` prove the companion plugins properly: it reads the `Version:` header out of `bp-restrict/bp-restrict.php` and checks whether `buddypress/buddypress.php` and `paid-memberships-pro/paid-memberships-pro.php` exist in the same tree. `--access-log` greps for `{${` in request URIs — the exploit's calling card.

Exit codes: `0` patched / not exposed / no log hits, `1` vulnerable or log hits found, `2` unknown, `3` usage error.

## `Traps`

* The early-fix trap. The vendor shipped `1.5.5` on `12 Nov 2026`, nine days before the `CVE` record was published on `21 Nov`. A site that updated any time after the 12th is already fixed — and some trackers still list "no fix" for this `CVE`, because they read the `CVE` record and never looked at the release. This scanner grades against the vendor release, not the tracker lag.
* The `1.5.4` trap. `1.5.4` is the last vulnerable release, one patch behind the fix, and it was the current release on the day the `CVE` dropped. "Latest before the `CVE`" is not "patched". This scanner says so out loud.
* The slug trap. The installed plugin directory is `bp-restrict` — `restrictions-for-buddypress` is only the `wordpress.org` search URL. Looking in the wrong directory grades a vulnerable install `UNKNOWN`. `--local` looks for `bp-restrict` and tells you when it is not there.
* The precondition trap. This flaw needs `BuddyPress` and `Paid Memberships Pro` both active. A site running the plugin alone is not exposed — but do not guess that from the outside: `--url` cannot prove the companions are absent, so it grades on version and tells you to confirm locally. `--wp-root` proves it for you.
* The readme-blocked trap. Some hosts return `403` or `404` for plugin readme files even when the plugin is installed. A blocked readme grades `UNKNOWN`, never `FIXED` — grade it locally with `--wp-root` instead.
* The patch-is-not-enough trap. Patching closes the hole, it does not undo a break-in. This is unauthenticated `RCE` with public exploit code, so a vulnerable install may already be owned. Patch, then rotate database passwords and `WordPress` salts, and hunt the access logs for `{${` in request URIs. `--access-log` checks the published pattern for you, and no hits in the logs checked is not a clean bill — logs rotate and attackers clean up.
* The `WAF` trap. Blocking requests containing `/{${` buys time, it is not a fix. The vulnerable `eval()` is still there for any bypass. Update.

## `Sources`

* `Wordfence` (CNA), `CVE-2026-120539` published `2026-11-21 05:35 UTC` (primary source for the `9.8` rating, the mechanism and the affected range `<= 1.5.4`)
* `NVD`, `CVE-2026-120539` (corroborates the description, vector and affected range; status `Deferred` / not yet enriched as of `2026-11-23`)
* `seventhqueen/buddypress-restrict` release `1.5.5` (`12 Nov 2026`, primary source for the fix: "Fixed unauthenticated `PHP` code injection via the request URI in restriction condition evaluation")
* `cve.now` timeline (`21 Nov 2026`, public exploit code `LLCForge/CVE-2026-120539` at `08:12 UTC`; not in `CISA KEV` as of `2026-11-21`; `EPSS` ~`2.2%`)
* `WordPress.org` plugin listing (slug `bp-restrict`, confirmed against the `plugins.trac` paths the `NVD` record cites)

Where sources disagree, this scanner follows the vendor release and says so. The one live disagreement is the fix itself: several trackers list "no fix" for this `CVE`, because the `CVE` record carries no fixed-version field — the vendor release `1.5.5` (nine days older than the `CVE` record) is the fix, and that is what this tool grades against.

## `Related work`

No `nuclei` template for `CVE-2026-120539` existed as of `2026-11-23`, and no `foxcornlab` scanner covered `BuddyPress` before this one. A public exploit (`LLCForge`, `21 Nov`) exists; this tool is the defensive counterpart: version grading against the vendor table, a readme-only remote probe, and the access-log hunt, all without sending exploit traffic.

## `Thanks to`

* `Wordfence` — for the `CNA` record and the affected-version range
* `seventhqueen` — for shipping the `1.5.5` fix nine days before the `CVE` record, and for the release note that names the flaw plainly
* `LLCForge` — for the public exploit that set the clock on this one (defenders move faster when the code is public)

Educational and defensive use only. This tool detects exposure, it does not exploit anything. If you run `Restrictions for BuddyPress` with `BuddyPress` and `Paid Memberships Pro`, update it to `1.5.5` — then hunt, because patching alone does not evict an attacker who already ran code on your box.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
