# Security checks modeled loosely on the CIS Apple macOS Benchmark
# (https://www.cisecurity.org/benchmark/apple_os). Not a certified
# CIS-CAT scan, just a simplified version for my own project.
#
# Each check function returns a dict:
#   id, title, category, status (PASS/FAIL/WARN/SKIP), details, remediation, reference
#
# Remote Login and Remote Apple Events need sudo to check for real,
# so those report WARN instead of guessing when they can't confirm.

import platform
import re
import subprocess

IS_MACOS = platform.system() == "Darwin"


def _run(cmd, timeout=6):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


def _skip_not_macos(check_id, title, category, reference, expected):
    return {
        "id": check_id,
        "title": title,
        "category": category,
        "status": "SKIP",
        "details": f"This check targets macOS and does not apply on {platform.system()}",
        "remediation": f"On macOS, ensure: {expected}",
        "reference": reference,
    }


def _needs_privilege(check_id, title, category, reference, expected):
    return {
        "id": check_id,
        "title": title,
        "category": category,
        "status": "WARN",
        "details": "Could not confirm, this check needs admin rights. Re-run with 'sudo python3 scanner.py' for a real answer.",
        "remediation": expected,
        "reference": reference,
    }


# ---------------------------------------------------------------------
# 1. System integrity
# ---------------------------------------------------------------------

def check_sip_enabled():
    if not IS_MACOS:
        return _skip_not_macos("1.1", "System Integrity Protection (SIP) is enabled",
                                "System Integrity", "CIS 5.1.1", "csrutil status reports 'enabled'")
    rc, out, err = _run("csrutil status")
    if rc != 0:
        return {
            "id": "1.1", "title": "System Integrity Protection (SIP) is enabled",
            "category": "System Integrity", "status": "SKIP",
            "details": f"Could not run csrutil: {err or out}",
            "remediation": "Boot into Recovery Mode and run 'csrutil enable'",
            "reference": "CIS 5.1.1",
        }
    ok = "enabled" in out.lower()
    return {
        "id": "1.1", "title": "System Integrity Protection (SIP) is enabled",
        "category": "System Integrity", "status": "PASS" if ok else "FAIL",
        "details": out,
        "remediation": "Boot into Recovery Mode, open Terminal, and run 'csrutil enable', then restart",
        "reference": "CIS 5.1.1",
    }


def check_gatekeeper_enabled():
    if not IS_MACOS:
        return _skip_not_macos("1.2", "Gatekeeper is enabled", "System Integrity",
                                "CIS 2.5.2", "spctl --status reports 'assessments enabled'")
    rc, out, err = _run("spctl --status")
    ok = rc == 0 and "assessments enabled" in out.lower()
    return {
        "id": "1.2", "title": "Gatekeeper is enabled", "category": "System Integrity",
        "status": "PASS" if ok else "FAIL",
        "details": out or err or "No output from spctl",
        "remediation": "Run: sudo spctl --master-enable, or enable it under System Settings > Privacy & Security",
        "reference": "CIS 2.5.2",
    }


# ---------------------------------------------------------------------
# 2. Encryption
# ---------------------------------------------------------------------

def check_filevault_enabled():
    if not IS_MACOS:
        return _skip_not_macos("2.1", "FileVault disk encryption is enabled", "Encryption",
                                "CIS 2.6.1.1", "fdesetup status reports 'FileVault is On.'")
    rc, out, err = _run("fdesetup status")
    if rc != 0:
        return {
            "id": "2.1", "title": "FileVault disk encryption is enabled",
            "category": "Encryption", "status": "SKIP",
            "details": f"Could not run fdesetup: {err or out}",
            "remediation": "Enable under System Settings > Privacy & Security > FileVault",
            "reference": "CIS 2.6.1.1",
        }
    ok = "filevault is on" in out.lower()
    return {
        "id": "2.1", "title": "FileVault disk encryption is enabled", "category": "Encryption",
        "status": "PASS" if ok else "FAIL",
        "details": out,
        "remediation": "Enable under System Settings > Privacy & Security > FileVault",
        "reference": "CIS 2.6.1.1",
    }


# ---------------------------------------------------------------------
# 3. Firewall & remote access
# ---------------------------------------------------------------------

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def check_firewall_enabled():
    if not IS_MACOS:
        return _skip_not_macos("3.1", "The built-in Application Firewall is enabled", "Firewall & Network",
                                "CIS 3.6.1", f"{_SOCKETFILTERFW} --getglobalstate reports the firewall is on")
    rc, out, err = _run(f"{_SOCKETFILTERFW} --getglobalstate")
    if rc != 0:
        return {
            "id": "3.1", "title": "The built-in Application Firewall is enabled",
            "category": "Firewall & Network", "status": "SKIP",
            "details": f"Could not query firewall state: {err or out}",
            "remediation": "Enable under System Settings > Network > Firewall",
            "reference": "CIS 3.6.1",
        }
    ok = "state = 1" in out.lower() or "enabled" in out.lower()
    return {
        "id": "3.1", "title": "The built-in Application Firewall is enabled",
        "category": "Firewall & Network", "status": "PASS" if ok else "FAIL",
        "details": out,
        "remediation": "Enable under System Settings > Network > Firewall",
        "reference": "CIS 3.6.1",
    }


def check_firewall_stealth_mode():
    if not IS_MACOS:
        return _skip_not_macos("3.2", "Firewall stealth mode is enabled", "Firewall & Network",
                                "CIS 3.6.3", f"{_SOCKETFILTERFW} --getstealthmode reports stealth mode is on")
    rc, out, err = _run(f"{_SOCKETFILTERFW} --getstealthmode")
    if rc != 0:
        return {
            "id": "3.2", "title": "Firewall stealth mode is enabled",
            "category": "Firewall & Network", "status": "SKIP",
            "details": f"Could not query stealth mode: {err or out}",
            "remediation": "Enable under System Settings > Network > Firewall > Options > Enable Stealth Mode",
            "reference": "CIS 3.6.3",
        }
    ok = "enabled" in out.lower()
    return {
        "id": "3.2", "title": "Firewall stealth mode is enabled",
        "category": "Firewall & Network", "status": "PASS" if ok else "FAIL",
        "details": out,
        "remediation": "Enable under System Settings > Network > Firewall > Options > Enable Stealth Mode",
        "reference": "CIS 3.6.3",
    }


def check_remote_login_disabled():
    if not IS_MACOS:
        return _skip_not_macos("3.3", "Remote Login (SSH) is disabled unless needed", "Firewall & Network",
                                "CIS 2.3.3.1", "systemsetup -getremotelogin reports Off")
    rc, out, err = _run("systemsetup -getremotelogin")
    combined = f"{out} {err}".lower()
    if "administrator" in combined or rc != 0:
        return _needs_privilege("3.3", "Remote Login (SSH) is disabled unless needed",
                                 "Firewall & Network", "CIS 2.3.3.1",
                                 "If SSH access isn't needed, disable it: sudo systemsetup -setremotelogin off")
    ok = "off" in combined
    return {
        "id": "3.3", "title": "Remote Login (SSH) is disabled unless needed",
        "category": "Firewall & Network", "status": "PASS" if ok else "WARN",
        "details": out,
        "remediation": "If SSH access isn't needed, disable it: sudo systemsetup -setremotelogin off",
        "reference": "CIS 2.3.3.1",
    }


def check_remote_apple_events_disabled():
    if not IS_MACOS:
        return _skip_not_macos("3.4", "Remote Apple Events are disabled", "Firewall & Network",
                                "CIS 2.3.3.4", "systemsetup -getremoteappleevents reports Off")
    rc, out, err = _run("systemsetup -getremoteappleevents")
    combined = f"{out} {err}".lower()
    if "administrator" in combined or rc != 0:
        return _needs_privilege("3.4", "Remote Apple Events are disabled",
                                 "Firewall & Network", "CIS 2.3.3.4",
                                 "sudo systemsetup -setremoteappleevents off")
    ok = "off" in combined
    return {
        "id": "3.4", "title": "Remote Apple Events are disabled",
        "category": "Firewall & Network", "status": "PASS" if ok else "WARN",
        "details": out,
        "remediation": "Run: sudo systemsetup -setremoteappleevents off",
        "reference": "CIS 2.3.3.4",
    }


def check_sharing_services_disabled():
    if not IS_MACOS:
        return _skip_not_macos("3.5", "File and screen sharing services are disabled", "Firewall & Network",
                                "CIS 2.3.3", "smbd and screensharing are not loaded as launch daemons")
    findings = []
    for label in ["com.apple.smbd", "com.apple.screensharing"]:
        rc, out, err = _run(f"launchctl print system/{label}")
        loaded = rc == 0
        findings.append((label, loaded))
    active = [label for label, loaded in findings if loaded]
    ok = len(active) == 0
    return {
        "id": "3.5", "title": "File and screen sharing services are disabled",
        "category": "Firewall & Network", "status": "PASS" if ok else "FAIL",
        "details": "None active" if ok else f"Active: {', '.join(active)}",
        "remediation": "Disable under System Settings > General > Sharing",
        "reference": "CIS 2.3.3",
    }


# ---------------------------------------------------------------------
# 4. Software updates
# ---------------------------------------------------------------------

def check_auto_update_check_enabled():
    if not IS_MACOS:
        return _skip_not_macos("4.1", "Automatic update checking is enabled", "Software Updates",
                                "CIS 1.1", "AutomaticCheckEnabled is true in com.apple.SoftwareUpdate")
    rc, out, err = _run("defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled")
    if rc != 0:
        return {
            "id": "4.1", "title": "Automatic update checking is enabled",
            "category": "Software Updates", "status": "SKIP",
            "details": f"Could not read preference: {err or out}",
            "remediation": "Enable under System Settings > General > Software Update",
            "reference": "CIS 1.1",
        }
    ok = out.strip() == "1"
    return {
        "id": "4.1", "title": "Automatic update checking is enabled", "category": "Software Updates",
        "status": "PASS" if ok else "FAIL",
        "details": f"AutomaticCheckEnabled = {out.strip()}",
        "remediation": "Enable under System Settings > General > Software Update",
        "reference": "CIS 1.1",
    }


def check_auto_security_updates_enabled():
    if not IS_MACOS:
        return _skip_not_macos("4.2", "Automatic security updates are installed", "Software Updates",
                                "CIS 1.3", "ConfigDataInstall and CriticalUpdateInstall are true")
    results = {}
    for key in ["ConfigDataInstall", "CriticalUpdateInstall"]:
        rc, out, err = _run(f"defaults read /Library/Preferences/com.apple.SoftwareUpdate {key}")
        results[key] = out.strip() if rc == 0 else None
    if all(v is None for v in results.values()):
        return {
            "id": "4.2", "title": "Automatic security updates are installed",
            "category": "Software Updates", "status": "SKIP",
            "details": "Could not read either preference key",
            "remediation": "Enable under System Settings > General > Software Update > Automatic Updates",
            "reference": "CIS 1.3",
        }
    ok = all(v == "1" for v in results.values() if v is not None)
    return {
        "id": "4.2", "title": "Automatic security updates are installed", "category": "Software Updates",
        "status": "PASS" if ok else "FAIL",
        "details": ", ".join(f"{k} = {v}" for k, v in results.items()),
        "remediation": "Enable under System Settings > General > Software Update > Automatic Updates",
        "reference": "CIS 1.3",
    }


# ---------------------------------------------------------------------
# 5. Authentication & screen lock
# ---------------------------------------------------------------------

def check_screensaver_password():
    if not IS_MACOS:
        return _skip_not_macos("5.1", "A password is required after screen saver / sleep", "Authentication",
                                "CIS 2.10.1", "askForPassword is 1 for com.apple.screensaver")
    rc, out, err = _run("defaults -currentHost read com.apple.screensaver askForPassword")
    if rc != 0:
        return {
            "id": "5.1", "title": "A password is required after screen saver / sleep",
            "category": "Authentication", "status": "SKIP",
            "details": f"Could not read preference: {err or out}",
            "remediation": "Enable under System Settings > Lock Screen > Require password",
            "reference": "CIS 2.10.1",
        }
    ok = out.strip() == "1"
    return {
        "id": "5.1", "title": "A password is required after screen saver / sleep",
        "category": "Authentication", "status": "PASS" if ok else "FAIL",
        "details": f"askForPassword = {out.strip()}",
        "remediation": "Enable under System Settings > Lock Screen > Require password after screen saver begins or display is turned off",
        "reference": "CIS 2.10.1",
    }


def check_screensaver_delay():
    if not IS_MACOS:
        return _skip_not_macos("5.2", "The password prompt appears immediately (5 seconds or less)",
                                "Authentication", "CIS 2.10.2", "askForPasswordDelay is 5 or less")
    rc, out, err = _run("defaults -currentHost read com.apple.screensaver askForPasswordDelay")
    if rc != 0:
        return {
            "id": "5.2", "title": "The password prompt appears immediately (5 seconds or less)",
            "category": "Authentication", "status": "SKIP",
            "details": f"Could not read preference (often unset, which defaults to immediate): {err or out}",
            "remediation": "Set Require password to 'immediately' under System Settings > Lock Screen",
            "reference": "CIS 2.10.2",
        }
    try:
        delay = float(out.strip())
    except ValueError:
        delay = None
    ok = delay is not None and delay <= 5
    return {
        "id": "5.2", "title": "The password prompt appears immediately (5 seconds or less)",
        "category": "Authentication", "status": "PASS" if ok else "FAIL",
        "details": f"askForPasswordDelay = {out.strip()} seconds",
        "remediation": "Set Require password to 'immediately' under System Settings > Lock Screen",
        "reference": "CIS 2.10.2",
    }


def check_automatic_login_disabled():
    if not IS_MACOS:
        return _skip_not_macos("5.3", "Automatic login is disabled", "Authentication",
                                "CIS 2.3.1.1", "no autoLoginUser key is set in com.apple.loginwindow")
    rc, out, err = _run("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser")
    key_missing = rc != 0 and ("does not exist" in err.lower() or "does not exist" in out.lower())
    ok = key_missing
    return {
        "id": "5.3", "title": "Automatic login is disabled", "category": "Authentication",
        "status": "PASS" if ok else ("FAIL" if rc == 0 else "SKIP"),
        "details": "No auto-login user configured" if key_missing else (out or err),
        "remediation": "Disable under System Settings > Users & Groups > Login Options > Automatic login: Off",
        "reference": "CIS 2.3.1.1",
    }


def check_guest_account_disabled():
    if not IS_MACOS:
        return _skip_not_macos("5.4", "The Guest account is disabled", "Authentication",
                                "CIS 2.6.4", "sysadminctl -guestAccount status reports it is off")
    rc, out, err = _run("sysadminctl -guestAccount status")
    combined = f"{out} {err}".lower()
    if not combined.strip():
        return {
            "id": "5.4", "title": "The Guest account is disabled", "category": "Authentication",
            "status": "SKIP", "details": "No output from sysadminctl",
            "remediation": "Disable under System Settings > Users & Groups > Guest User",
            "reference": "CIS 2.6.4",
        }
    ok = "off" in combined
    return {
        "id": "5.4", "title": "The Guest account is disabled", "category": "Authentication",
        "status": "PASS" if ok else "FAIL",
        "details": (out or err).strip(),
        "remediation": "Disable under System Settings > Users & Groups > Guest User",
        "reference": "CIS 2.6.4",
    }


# ---------------------------------------------------------------------
# 6. Logging
# ---------------------------------------------------------------------

def check_audit_daemon_active():
    if not IS_MACOS:
        return _skip_not_macos("6.1", "The built-in security audit daemon (auditd) is active", "Logging",
                                "CIS 3.1", "com.apple.auditd is loaded")
    rc, out, err = _run("launchctl print system/com.apple.auditd")
    ok = rc == 0
    return {
        "id": "6.1", "title": "The built-in security audit daemon (auditd) is active", "category": "Logging",
        "status": "PASS" if ok else "WARN",
        "details": "auditd service is loaded" if ok else (err or "auditd service not found"),
        "remediation": "This is enabled by default on macOS; if disabled, contact your MDM/IT administrator",
        "reference": "CIS 3.1",
    }


ALL_CHECKS = [
    check_sip_enabled,
    check_gatekeeper_enabled,
    check_filevault_enabled,
    check_firewall_enabled,
    check_firewall_stealth_mode,
    check_remote_login_disabled,
    check_remote_apple_events_disabled,
    check_sharing_services_disabled,
    check_auto_update_check_enabled,
    check_auto_security_updates_enabled,
    check_screensaver_password,
    check_screensaver_delay,
    check_automatic_login_disabled,
    check_guest_account_disabled,
    check_audit_daemon_active,
]


def run_all_checks():
    results = []
    for check_fn in ALL_CHECKS:
        try:
            results.append(check_fn())
        except Exception as e:
            results.append({
                "id": "??",
                "title": check_fn.__name__,
                "category": "Error",
                "status": "SKIP",
                "details": f"Check raised an exception: {e}",
                "remediation": "N/A",
                "reference": "N/A",
            })
    return results
