#!/usr/local/sal/Python.framework/Versions/Current/bin/python3
# -*- coding: utf-8 -*-
"""
Sal checkin module: HomebrewAudit (filesystem-based)

Features:
- Detects system Homebrew presence by scanning filesystem
- Collects formulas & casks from /opt/homebrew/Cellar, /usr/local/Cellar,
  /opt/homebrew/Caskroom, /usr/local/Caskroom (name + version)
- Flags "unapproved" packages via blocklist (overridable file)
- Detects user-local Homebrew trees under /Users (without running them)
- Publishes human-readable facts + JSON for structured use
- Provides search-friendly fields for Sal reports
- Collects Homebrew taps (repos) for the system brew
- Flags non-standard Homebrew install prefix for the current CPU arch
"""

import os
import json
import subprocess
from datetime import datetime, timezone
from typing import Dict, List
import platform

import sal  # provided by the Sal client

__version__ = "2.1.0"

BLOCKLIST_FILE = "/usr/local/sal/homebrew_blocklist.txt"
DEFAULT_BLOCKLIST = [
    # override via /usr/local/sal/homebrew_blocklist.txt
    "ngrok", "nmap", "netcat", "socat", "john", "hashcat", "tor", "wireshark",
    "mitmproxy", "burpsuite", "adb", "fastboot", "terraform", "ansible",
    "pulumi", "aws", "azure-cli", "gcloud", "ffmpeg", "aria2", "curl", "wget",
]

CELLAR_PATHS = ["/opt/homebrew/Cellar", "/usr/local/Cellar"]
CASKROOM_PATHS = ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"]


# ----------------- helpers -----------------

def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def looks_like_root_block(out: str) -> bool:
    """Detect Homebrew's 'running as root' error so we can ignore it."""
    if not out:
        return False
    lowered = out.lower()
    return (
        "running as root is extremely dangerous" in lowered
        or lowered.startswith("error: running as root")
    )


def find_brew_root() -> str:
    """Best-effort: find brew for version string (optional)."""
    for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    try:
        out = subprocess.check_output(
            ["/bin/sh", "-c", "command -v brew"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return out
    except Exception:
        return ""


def run_cmd(cmd: List[str]):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output or ""
    except Exception:
        return 1, ""


def load_blocklist() -> List[str]:
    """Load blocklist from file, or fall back to DEFAULT_BLOCKLIST."""
    try:
        if os.path.isfile(BLOCKLIST_FILE):
            out: List[str] = []
            with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip().lower()
                    if s and not s.startswith("#"):
                        out.append(s)
            if out:
                return out
    except Exception:
        pass
    return [x.lower() for x in DEFAULT_BLOCKLIST]


def is_blocked(name: str, bl: List[str]) -> bool:
    n = (name or "").lower()
    return any(n == b or n.startswith(b) for b in bl)


def first_existing(paths: List[str]) -> str:
    for p in paths:
        if os.path.exists(p):
            return p
    return ""


def sha256_exe_under(path: str) -> str:
    """Return SHA256 of first executable under path, shallow walk."""
    try:
        if not path or not os.path.isdir(path):
            return ""
        for root, _dirs, files in os.walk(path):
            for fn in files:
                full = os.path.join(root, fn)
                try:
                    if os.path.isfile(full) and os.access(full, os.X_OK):
                        out = subprocess.check_output(
                            ["/usr/bin/shasum", "-a", "256", full],
                            text=True,
                            stderr=subprocess.DEVNULL,
                        )
                        return out.split()[0]
                except Exception:
                    continue
            break
    except Exception:
        pass
    return ""


def scan_cellar(path: str) -> List[Dict[str, str]]:
    """Return list of {name,version} by scanning a Cellar directory."""
    results: List[Dict[str, str]] = []
    if not os.path.isdir(path):
        return results
    try:
        for formula in os.listdir(path):
            fpath = os.path.join(path, formula)
            if not os.path.isdir(fpath):
                continue
            try:
                versions = sorted(os.listdir(fpath))
            except Exception:
                continue
            for ver in versions:
                vpath = os.path.join(fpath, ver)
                if os.path.isdir(vpath):
                    results.append({"name": formula, "version": ver})
    except Exception:
        pass
    return results


def scan_caskroom(path: str) -> List[Dict[str, str]]:
    """Return list of {name,version} by scanning a Caskroom directory."""
    results: List[Dict[str, str]] = []
    if not os.path.isdir(path):
        return results
    try:
        for cask in os.listdir(path):
            cpath = os.path.join(path, cask)
            if not os.path.isdir(cpath):
                continue
            try:
                versions = sorted(os.listdir(cpath))
            except Exception:
                continue
            for ver in versions:
                vpath = os.path.join(cpath, ver)
                if os.path.isdir(vpath):
                    results.append({"name": cask, "version": ver})
    except Exception:
        pass
    return results


def detect_user_local_brews() -> List[Dict[str, str]]:
    """
    Detect per-user Homebrew trees under /Users.

    We *don't* run them, just look for typical layouts:
      ~/homebrew, ~/.homebrew, ~/.linuxbrew, ~/.local/homebrew, ~/bin/brew
    """
    user_brews: List[Dict[str, str]] = []
    users_root = "/Users"
    if not os.path.isdir(users_root):
        return user_brews
    try:
        for entry in os.scandir(users_root):
            if not entry.is_dir():
                continue
            name = entry.name
            if name in ("Shared", ".localized") or name.startswith("."):
                continue
            home = entry.path
            roots = [
                os.path.join(home, "homebrew"),
                os.path.join(home, ".homebrew"),
                os.path.join(home, ".linuxbrew"),
                os.path.join(home, ".local", "homebrew"),
            ]
            brew_bins = [os.path.join(r, "bin", "brew") for r in roots] + [
                os.path.join(home, "bin", "brew"),
            ]
            found = []
            for brew_bin in brew_bins:
                if os.path.isfile(brew_bin) and os.access(brew_bin, os.X_OK):
                    tree_root = os.path.dirname(os.path.dirname(brew_bin))
                    found.append((brew_bin, tree_root))
            seen = set()
            for brew_path, tree_root in found:
                if brew_path in seen:
                    continue
                seen.add(brew_path)
                user_brews.append(
                    {"user": name, "brew_path": brew_path, "tree_root": tree_root}
                )
    except Exception:
        pass
    return user_brews


def get_arch() -> str:
    """Return machine architecture, e.g. arm64, x86_64."""
    try:
        return platform.machine() or ""
    except Exception:
        return ""


def get_brew_taps(brew_bin: str) -> List[str]:
    """
    Return list of taps (repos) for the system brew, e.g. homebrew/core.
    """
    if not brew_bin:
        return []
    rc, out = run_cmd([brew_bin, "tap"])
    if rc != 0 or not out or looks_like_root_block(out):
        return []
    taps: List[str] = []
    for line in out.splitlines():
        s = line.strip()
        if s:
            taps.append(s)
    return taps


def evaluate_brew_location(brew_bin: str) -> Dict[str, str]:
    """
    Determine Homebrew prefix and whether it matches the usual location
    for this CPU arch.

    arm64/aarch64: /opt/homebrew
    x86_64/i386:   /usr/local
    Unknown arch:  either /opt/homebrew or /usr/local considered OK
    """
    result = {
        "prefix": "",
        "location_ok": "",
        "note": "",
    }

    arch = get_arch()
    if brew_bin:
        prefix = os.path.dirname(os.path.dirname(brew_bin))
    else:
        prefix = ""

    result["prefix"] = prefix

    if not prefix:
        # No brew binary found even if Cellars might exist
        result["location_ok"] = "no"
        result["note"] = f"brew binary not found (arch {arch})"
        return result

    if arch in ("arm64", "aarch64"):
        expected = ["/opt/homebrew"]
    elif arch in ("x86_64", "i386"):
        expected = ["/usr/local"]
    else:
        expected = ["/opt/homebrew", "/usr/local"]

    location_ok = prefix in expected
    result["location_ok"] = "yes" if location_ok else "no"

    if location_ok:
        result["note"] = ""
    else:
        result["note"] = (
            f"brew at {prefix} for arch {arch}, expected "
            f"{', '.join(expected)}"
        )

    return result


# ----------------- main logic -----------------

def main() -> None:
    submission: Dict = sal.get_checkin_results().get("HomebrewAudit", {}) or {}
    submission.setdefault("messages", [])
    submission["extra_data"] = {"checkin_module_version": __version__}

    facts_raw: Dict[str, object] = {
        "timestamp": utc_iso(),
        "brew_present": "no",
        "brew_version": "",
        "homebrew_formulas": [],
        "homebrew_casks": [],
        "homebrew_unapproved": [],
        "homebrew_user_brew_trees_raw": [],
        "homebrew_taps": [],
        "homebrew_prefix": "",
        "homebrew_location_ok": "",
        "homebrew_location_note": "",
    }

    # Detect brew presence via filesystem
    any_cellar = any(os.path.isdir(p) for p in CELLAR_PATHS)
    any_caskroom = any(os.path.isdir(p) for p in CASKROOM_PATHS)
    if any_cellar or any_caskroom:
        facts_raw["brew_present"] = "yes"

    # Best-effort brew version (ignore 'running as root' error text)
    brew_bin = find_brew_root()
    if brew_bin:
        rc, vout = run_cmd([brew_bin, "--version"])
        if vout and not looks_like_root_block(vout):
            facts_raw["brew_version"] = vout.splitlines()[0].strip()

        # Collect taps (repos) for this brew
        taps = get_brew_taps(brew_bin)
        facts_raw["homebrew_taps"] = taps

        # Evaluate install location relative to arch
        loc_info = evaluate_brew_location(brew_bin)
        facts_raw["homebrew_prefix"] = loc_info.get("prefix", "")
        facts_raw["homebrew_location_ok"] = loc_info.get("location_ok", "")
        facts_raw["homebrew_location_note"] = loc_info.get("note", "")
    else:
        # No brew bin but cellars might exist -> flag as suspicious location
        loc_info = evaluate_brew_location("")
        facts_raw["homebrew_prefix"] = loc_info.get("prefix", "")
        facts_raw["homebrew_location_ok"] = loc_info.get("location_ok", "")
        facts_raw["homebrew_location_note"] = loc_info.get("note", "")

    # Scan formulas/casks from filesystem
    formulas: List[Dict[str, str]] = []
    for path in CELLAR_PATHS:
        formulas.extend(scan_cellar(path))

    casks: List[Dict[str, str]] = []
    for path in CASKROOM_PATHS:
        casks.extend(scan_caskroom(path))

    facts_raw["homebrew_formulas"] = formulas
    facts_raw["homebrew_casks"] = casks

    # Unapproved (system-level)
    bl = load_blocklist()
    unapproved: List[Dict[str, str]] = []
    for item in (formulas + casks):
        name = item.get("name") or ""
        ver = item.get("version") or "unknown"
        if not name or not is_blocked(name, bl):
            continue
        lname = name.lower()
        candidates = [
            f"/opt/homebrew/Cellar/{lname}/{ver}",
            f"/usr/local/Cellar/{lname}/{ver}",
            f"/opt/homebrew/bin/{lname}",
            f"/usr/local/bin/{lname}",
            f"/Applications/{name}.app",
        ]
        path = first_existing(candidates)
        sha = sha256_exe_under(path) if os.path.isdir(path) else ""
        unapproved.append({"pkg": lname, "version": ver, "path": path, "sha256": sha})
    facts_raw["homebrew_unapproved"] = unapproved

    # user-local brews
    facts_raw["homebrew_user_brew_trees_raw"] = detect_user_local_brews()

    _publish(submission, facts_raw)


def _publish(submission: Dict, facts_raw: Dict[str, object]) -> None:
    formulas = facts_raw["homebrew_formulas"]  # type: ignore[assignment]
    casks = facts_raw["homebrew_casks"]        # type: ignore[assignment]
    unapproved = facts_raw["homebrew_unapproved"]  # type: ignore[assignment]
    user_brews = facts_raw.get("homebrew_user_brew_trees_raw", []) or []
    taps = facts_raw.get("homebrew_taps", []) or []

    # JSON backups for structured export
    formulas_json = json.dumps(formulas, separators=(",", ":"))
    casks_json = json.dumps(casks, separators=(",", ":"))
    unapproved_json = json.dumps(unapproved, separators=(",", ":"))
    user_brews_json = json.dumps(user_brews, separators=(",", ":"))
    taps_json = json.dumps(taps, separators=(",", ":"))

    # Human-readable lists
    formulas_csv = ", ".join(f'{i["name"]} {i["version"]}' for i in formulas) or "(none)"
    casks_csv = ", ".join(f'{i["name"]} {i["version"]}' for i in casks) or "(none)"
    taps_csv = ", ".join(taps) or "(none)"

    # Unapproved summary
    names = ",".join(sorted({d.get("pkg", "") for d in unapproved if d.get("pkg")}))
    pairs = ",".join(
        f'{d.get("pkg","")}:{d.get("version","unknown")}'
        for d in unapproved
        if d.get("pkg")
    )
    count = str(len(unapproved))

    # User-local summary
    users = ",".join(sorted({d.get("user", "") for d in user_brews if d.get("user")}))
    user_brew_count = str(len(user_brews))

    facts_for_ui: Dict[str, str] = {
        "timestamp": str(facts_raw["timestamp"]),
        "brew_present": str(facts_raw["brew_present"]),
        "brew_version": str(facts_raw["brew_version"]),

        # primary, human-readable facts
        "homebrew_formulas": formulas_csv,
        "homebrew_casks": casks_csv,

        "homebrew_unapproved": pairs or "(none)",
        "homebrew_unapproved_count": count,
        "homebrew_unapproved_names": names or "(none)",
        "homebrew_unapproved_pairs": pairs or "(none)",

        "homebrew_user_brew_trees": users or "(none)",
        "homebrew_user_brew_trees_count": user_brew_count,
        "homebrew_user_brew_users": users or "(none)",

        # taps / repos
        "homebrew_taps": taps_csv,
        "homebrew_taps_json": taps_json,

        # install location / correctness
        "homebrew_prefix": str(facts_raw.get("homebrew_prefix", "")),
        "homebrew_location_ok": str(facts_raw.get("homebrew_location_ok", "")),
        "homebrew_location_note": str(facts_raw.get("homebrew_location_note", "")),

        # JSON backups for structured export
        "homebrew_formulas_json": formulas_json,
        "homebrew_casks_json": casks_json,
        "homebrew_unapproved_json": unapproved_json,
        "homebrew_user_brew_trees_json": user_brews_json,
    }

    submission["facts"] = facts_for_ui
    sal.set_checkin_results("HomebrewAudit", submission)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sub: Dict = sal.get_checkin_results().get("HomebrewAudit", {}) or {}
        sub.setdefault("messages", [])
        sub["messages"].append(
            {"message_type": "ERROR", "text": f"HomebrewAudit fatal: {e}"}
        )
        sub["facts"] = {
            "timestamp": utc_iso(),
            "brew_present": "no",
            "brew_version": "",
            "homebrew_formulas": "(none)",
            "homebrew_casks": "(none)",
            "homebrew_unapproved": "(none)",
            "homebrew_unapproved_count": "0",
            "homebrew_unapproved_names": "(none)",
            "homebrew_unapproved_pairs": "(none)",
            "homebrew_user_brew_trees": "(none)",
            "homebrew_user_brew_trees_count": "0",
            "homebrew_user_brew_users": "(none)",
            "homebrew_taps": "(none)",
            "homebrew_taps_json": "[]",
            "homebrew_prefix": "",
            "homebrew_location_ok": "",
            "homebrew_location_note": "",
            "homebrew_formulas_json": "[]",
            "homebrew_casks_json": "[]",
            "homebrew_unapproved_json": "[]",
            "homebrew_user_brew_trees_json": "[]",
        }
        sal.set_checkin_results("HomebrewAudit", sub)

