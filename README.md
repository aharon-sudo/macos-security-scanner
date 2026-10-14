# macOS Security Compliance Scanner

A command line tool that checks your Mac's security settings against the CIS Apple macOS Benchmark, the hardening checklist that real IT and security teams use to audit Mac fleets. Written in Python, no external libraries needed.

## Why I built this

I'm a cybersecurity student and I wanted something more than coursework to show for it. Most security audits come down to the same question: is this machine actually configured the way it's supposed to be? Enterprise tools like CIS-CAT and Apple's own macOS Security Compliance Project do this at scale for managed fleets. I wanted to build a small version myself to understand how that actually works under the hood, reading system preferences, calling `csrutil`, `spctl`, `fdesetup`, checking which services are running, and turning all of that into a real pass/fail report.

It checks 15 controls across six areas:

| Category | What it checks |
|---|---|
| System Integrity | System Integrity Protection (SIP), Gatekeeper |
| Encryption | FileVault |
| Firewall & Network | Application Firewall, stealth mode, Remote Login (SSH), Remote Apple Events, file/screen sharing |
| Software Updates | Automatic update checking, automatic security updates |
| Authentication | Screen lock password + delay, automatic login, guest account |
| Logging | Built-in audit daemon (auditd) |

## How to run it

```bash
python3 scanner.py
```

You'll get a color-coded terminal report:

```
CIS macOS Benchmark Compliance Scanner
Host: Aharons-MacBook-Pro.local  |  OS: Darwin 24.6.0
Scan time: 2026-09-03T14:34:49
----------------------------------------------------------------------

System Integrity
  [PASS] 1.1   System Integrity Protection (SIP) is enabled
          SIP status: enabled.
  [PASS] 1.2   Gatekeeper is enabled
          assessments enabled
...
Summary: 9 passed, 3 failed, 2 warnings, 1 skipped (of 15 checks)
Compliance score: 75.0% (based on 12 pass/fail-applicable checks)
```

Two checks (Remote Login and Remote Apple Events) need admin rights to answer for sure. If those come back WARN, run it again with `sudo python3 scanner.py`.

### HTML report

```bash
python3 scanner.py --html report.html
```

Writes a standalone HTML report you can open in a browser or screenshot.

### JSON output

```bash
python3 scanner.py --json results.json
```

For piping into something else, or a CI pipeline.

### Fail a build under a threshold

```bash
python3 scanner.py --fail-under 80
```

Exits non-zero if the score is below the number you give it. Could be dropped into a CI check for build machines.

## How it's built

Every check lives in `checks.py` as its own function. Each one returns an ID, a title, a category, a status (PASS/FAIL/WARN/SKIP), what it actually found, and how to fix it if it fails. `scanner.py` runs all of them, tallies a score, and prints or exports the result. Adding a new check just means writing a new function with the same shape and dropping it into the `ALL_CHECKS` list at the bottom of `checks.py`.

Checks that need root but don't have it report WARN instead of guessing. Run this on something other than macOS and every check reports SKIP with an explanation instead of a false result, so it fails safe instead of lying.

## Limitations

This isn't a certified compliance tool and it doesn't replace a real audit or Apple's own MSCP tooling. Some checks are simplified versions of the full CIS control. Two require sudo to give a confirmed answer.

## Requirements

- Python 3.7+, macOS
- Standard library only, nothing to install

## License

MIT, see LICENSE.
