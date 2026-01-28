#!/usr/local/sal/Python.framework/Versions/Current/bin/python3
# -*- coding: utf-8 -*-

# Sal checkin module: salbrowserext (diagnostic v1.2.3)
# - Same features as v1.2.2, plus early import-time logging (before 'import sal')
# - Captures Python executable/version, sys.path, and module file SHA256
# - If 'import sal' fails, logs the traceback to module log

import sys
import os
import hashlib
import json
import re
import plistlib
import pwd
import subprocess
import time
import traceback
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional, Set

__version__ = "1.2.3"
MODULE_NAME = "salbrowserext"
LOG_PATH = "/usr/local/sal/var/log/salbrowserext.log"

def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _log(msg: str) -> None:
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{_utc_iso()} [{MODULE_NAME}] {msg}\n")
    except Exception:
        # Logging must never interfere with Sal checkin; ignore all logging errors.
        pass

# --- EARLY DIAGNOSTICS (before import sal) ---
try:
    fpath = os.path.abspath(__file__)
except Exception:
    fpath = "<unknown>"

sha256 = "<unreadable>"
try:
    h = hashlib.sha256()
    with open(fpath, "rb") as fp:
        for chunk in iter(lambda: fp.read(65536), b""):
            h.update(chunk)
    sha256 = h.hexdigest()
except Exception as e:
    sha256 = f"<hash_error:{e}>"

try:
    _log(f"import precheck v{__version__} file={fpath} sha256={sha256}")
    _log(f"python={sys.executable} version={sys.version.splitlines()[0]}")
    _log(f"sys.path[:5]={sys.path[:5]}")
except Exception:
    pass

# Try to import sal with diagnostics
try:
    import sal  # provided by Sal client env
    _log("import sal OK")
except Exception as e:
    _log(f"import sal FAILED: {e}\n{traceback.format_exc()}")
    # We can't submit facts without sal; exit to avoid NameError later in main().
    sys.exit(0)
# -------------------
# Tunables
# -------------------
ACTIVE_USER_ONLY = True           # safer for submit context
INCLUDE_CHROMIUM_PERMISSIONS = True
PERMISSIONS_TRUNCATE = 30
RAW_JSON_TRUNCATE = 80000
MAX_FLATTENED_EXTENSIONS = 8000
SAFARI_APP_SCAN_TIMEOUT = 10.0

SAFARI_APP_SCAN_DIRS = [
    "/Applications",
    "/System/Applications",
    os.path.expanduser("~/Applications"),
]

SENSITIVE_PERMISSIONS = {
    "tabs","history","webRequest","webRequestBlocking","downloads","clipboardRead",
    "clipboardWrite","bookmarks","management","nativeMessaging","cookies","privacy",
    "proxy","debugger","declarativeNetRequestWithHostAccess","declarativeNetRequestFeedback",
}
BROAD_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
_key_re = re.compile(r"[^a-zA-Z0-9]+")

def normalize_key(component: str) -> str:
    c = _key_re.sub("_", (component or "")).strip("_")
    c = re.sub(r"_+", "_", c)
    return c.lower()

def to_string(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(",", ":"))
    return "" if v is None else str(v)

def chrome_time_to_iso(chrome_time: Any) -> str:
    # Chrome time is microseconds since 1601-01-01 UTC. Guard against
    # negative or out-of-range values to avoid producing invalid dates.
    try:
        micro = int(str(chrome_time))
    except Exception:
        return to_string(chrome_time)

    if micro < 0:
        # Negative Chrome timestamps are invalid; fall back to raw value.
        return to_string(chrome_time)

    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=micro)
        # Defensive check: ensure we did not wrap before the epoch.
        if dt < epoch:
            return to_string(chrome_time)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return to_string(chrome_time)
def safe_read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def safe_read_plist(path: str) -> Optional[Any]:
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None

def run_stat_console_user() -> Optional[str]:
    try:
        out = subprocess.check_output(["/usr/bin/stat","-f","%Su","/dev/console"], text=True).strip()
        if out and out != "root":
            return out
    except Exception as e:
        _log(f"run_stat_console_user error: {e}")
    return None

def list_human_user_homes() -> List[Tuple[str,str]]:
    try:
        if ACTIVE_USER_ONLY:
            cu = run_stat_console_user()
            if cu:
                try:
                    pwent = pwd.getpwnam(cu)
                    if pwent.pw_uid >= 500 and pwent.pw_dir.startswith("/Users/") and os.path.isdir(pwent.pw_dir):
                        return [(pwent.pw_name, pwent.pw_dir)]
                except KeyError:
                    pass
        users: List[Tuple[str,str]] = []
        for pwent in pwd.getpwall():
            try:
                if pwent.pw_uid < 500: continue
                home = pwent.pw_dir or ""
                if not home.startswith("/Users/"): continue
                if not os.path.isdir(home): continue
                users.append((pwent.pw_name, home))
            except Exception:
                continue
        return users
    except Exception as e:
        _log(f"list_human_user_homes error: {e}")
        return []

# --- Risk & perms helpers ---
def chromium_permissions_from_manifest(manifest: dict) -> Tuple[List[str], List[str]]:
    perms = manifest.get("permissions") or []
    host_perms = manifest.get("host_permissions") or []
    p = [str(x) for x in perms if isinstance(x, str)]
    h = [str(x) for x in host_perms if isinstance(x, str)]
    p_hosts = [x for x in p if x in BROAD_HOST_PATTERNS or "://" in x or x.endswith("/*")]
    host_all = list(dict.fromkeys(h + p_hosts))
    return p, host_all

def chromium_risk_from_permissions(perms: List[str], host_perms: List[str]) -> Tuple[int,str,List[str]]:
    reasons: List[str] = []
    score = 0
    if any(h in BROAD_HOST_PATTERNS for h in host_perms):
        score += 5; reasons.append("broad_host_access")
    sens_hits = sorted(set(p for p in perms if p in SENSITIVE_PERMISSIONS))
    if sens_hits:
        score += min(4, len(sens_hits)); reasons.append("sensitive_perms:"+",".join(sens_hits[:6]))
    if "nativeMessaging" in perms:
        score += 1
        if not any("nativeMessaging" in r for r in reasons):
            reasons.append("nativeMessaging")
    score = max(0, min(10, score))
    level = "low" if score < 3 else ("medium" if score < 7 else "high")
    return score, level, reasons

def chromium_install_type_from_meta(meta: dict, manifest: dict) -> str:
    location = meta.get("location")
    if location == 5: return "policy"
    if meta.get("was_installed_by_default"): return "default"
    if meta.get("from_webstore"): return "webstore"
    up = (manifest or {}).get("update_url") or ""
    if "google.com/service/update2/crx" in up or "edge.microsoft.com" in up:
        return "webstore"
    return "normal"

# --- Safari collectors ---
def collect_safari_plist_for_user(user: str, home: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    try:
        cont_plist = os.path.join(home,"Library","Containers","com.apple.Safari","Data","Library","Safari","Extensions","Extensions.plist")
        legacy_plist = os.path.join(home,"Library","Safari","Extensions","Extensions.plist")
        for plist_path in (cont_plist, legacy_plist):
            plist_data = safe_read_plist(plist_path)
            if not plist_data: continue
            installed = plist_data.get("Installed Extensions") or plist_data.get("InstalledExtensions") or []
            if not isinstance(installed, list): continue
            for item in installed:
                try:
                    results.append({
                        "browser":"safari","user":user,"profile":"default",
                        "id": item.get("Identifier") or item.get("Bundle Identifier") or item.get("AppIdentifier") or "",
                        "name": item.get("Name") or item.get("Bundle Name") or "",
                        "version": item.get("Version") or "",
                        "enabled": bool(item.get("Enabled", False)),
                        "type":"app-extension","path": item.get("Archive File Name") or item.get("Bundle Directory") or "",
                        "source":"plist","install_type":"user",
                    })
                except Exception:
                    continue
    except Exception as e:
        _log(f"collect_safari_plist_for_user error ({user}): {e}")
    return results

def iter_app_bundles(time_budget: float) -> List[str]:
    apps: List[str] = []
    t0 = time.time()
    for root in SAFARI_APP_SCAN_DIRS:
        if time.time() - t0 > time_budget: break
        if not os.path.isdir(root): continue
        try:
            for name in os.listdir(root):
                if time.time() - t0 > time_budget: break
                if not name.endswith(".app"): continue
                path = os.path.join(root, name)
                if os.path.isdir(path): apps.append(path)
        except Exception:
            continue
    return apps

def scan_app_for_safari_extensions(app_path: str) -> List[Dict[str,str]]:
    results: List[Dict[str,str]] = []
    plugdir = os.path.join(app_path,"Contents","PlugIns")
    if not os.path.isdir(plugdir): return results
    try:
        for item in os.listdir(plugdir):
            if not item.endswith(".appex"): continue
            appex = os.path.join(plugdir,item)
            info = safe_read_plist(os.path.join(appex,"Contents","Info.plist")) or {}
            ext = (info.get("NSExtension") or {})
            ident = ext.get("NSExtensionPointIdentifier","")
            if not isinstance(ident,str) or not ident.startswith("com.apple.Safari."): continue
            if "web-extension" in ident: ext_type="web-extension"
            elif "content-blocker" in ident: ext_type="content-blocker"
            else: ext_type="extension"
            name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or os.path.basename(appex)
            results.append({
                "browser":"safari","user":"","profile":"default",
                "id": info.get("CFBundleIdentifier",""), "name": name,
                "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "",
                "enabled":"","type":ext_type,"path":appex,"source":"app-scan","install_type":"app",
            })
    except Exception as e:
        _log(f"scan_app_for_safari_extensions error: {e}")
    return results

def collect_safari_for_user(user: str, home: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    dedup: Set[str] = set()
    for ext in collect_safari_plist_for_user(user, home):
        results.append(ext); dedup.add(ext.get("id",""))
    for app in iter_app_bundles(SAFARI_APP_SCAN_TIMEOUT):
        for ext in scan_app_for_safari_extensions(app):
            ext["user"]=user
            ext_id = ext.get("id","")
            if ext_id and ext_id in dedup: continue
            results.append(ext); 
            if ext_id: dedup.add(ext_id)
    return results

# --- Chromium collectors ---
def enumerate_chromium_profiles(base_dir: str) -> List[str]:
    profiles: List[str] = []
    try:
        for d in os.listdir(base_dir):
            p = os.path.join(base_dir,d)
            if not os.path.isdir(p): continue
            if os.path.isfile(os.path.join(p,"Preferences")) or os.path.isdir(os.path.join(p,"Extensions")):
                profiles.append(d)
    except Exception as e:
        _log(f"enumerate_chromium_profiles error for {base_dir}: {e}")
    return profiles

def chromium_fallback_scan_profile(base_profile: str, browser: str, user: str, profile: str, seen_ids: Set[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    ext_root = os.path.join(base_profile,"Extensions")
    if not os.path.isdir(ext_root): return results
    try:
        for ext_id in os.listdir(ext_root):
            id_dir = os.path.join(ext_root,ext_id)
            if not ext_id or not os.path.isdir(id_dir) or ext_id in seen_ids: continue
            versions = [v for v in os.listdir(id_dir) if os.path.isdir(os.path.join(id_dir,v))]
            if not versions: continue
            versions.sort(); ver = versions[-1]
            manifest_path = os.path.join(id_dir,ver,"manifest.json")
            manifest = safe_read_json(manifest_path) or {}
            perms, host_perms = chromium_permissions_from_manifest(manifest)
            score, level, reasons = chromium_risk_from_permissions(perms, host_perms)
            p_trunc = len(perms) > PERMISSIONS_TRUNCATE
            h_trunc = len(host_perms) > PERMISSIONS_TRUNCATE
            perms = perms[:PERMISSIONS_TRUNCATE]
            host_perms = host_perms[:PERMISSIONS_TRUNCATE]
            try:
                results.append({
                    "browser":browser,"user":user,"profile":profile,"id":ext_id,
                    "name": manifest.get("name",""), "version": manifest.get("version",ver),
                    "description": manifest.get("description",""), "enabled":"", 
                    "type":"extension" if not manifest.get("theme") else "theme",
                    "install_type":"unknown","install_source":"dir-scan","from_webstore":"","was_installed_by_default":"",
                    "path": manifest_path, "update_url": manifest.get("update_url",""), "homepage_url": manifest.get("homepage_url",""),
                    "install_time_iso":"", "permissions": perms, "host_permissions": host_perms,
                    "permissions_count": len(perms), "host_permissions_count": len(host_perms),
                    "permissions_truncated": p_trunc, "host_permissions_truncated": h_trunc,
                    "risk_score": score, "risk_level": level, "risk_reasons": reasons,
                })
                seen_ids.add(ext_id)
            except Exception:
                continue
    except Exception as e:
        _log(f"chromium_fallback_scan_profile error: {e}")
    return results

def collect_chromium_for_user(user: str, home: str, browser: str, app_support_rel: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    base = os.path.join(home,"Library","Application Support", *app_support_rel)
    if not os.path.isdir(base): return results
    profiles = enumerate_chromium_profiles(base)
    for profile in profiles:
        prof_dir = os.path.join(base,profile)
        prefs = safe_read_json(os.path.join(prof_dir,"Preferences")) or {}
        ext_settings = ((prefs.get("extensions") or {}).get("settings")) or {}
        seen_ids: Set[str] = set()
        if isinstance(ext_settings, dict) and ext_settings:
            for ext_id, meta in ext_settings.items():
                try:
                    manifest = meta.get("manifest") or {}
                    state = meta.get("state",0)
                    enabled = (state == 1) and not bool(meta.get("user_disabled", False))
                    perms, host_perms = chromium_permissions_from_manifest(manifest)
                    score, level, reasons = chromium_risk_from_permissions(perms, host_perms)
                    if not INCLUDE_CHROMIUM_PERMISSIONS:
                        perms, host_perms, p_trunc, h_trunc = [], [], False, False
                    else:
                        p_trunc = len(perms) > PERMISSIONS_TRUNCATE
                        h_trunc = len(host_perms) > PERMISSIONS_TRUNCATE
                        perms = perms[:PERMISSIONS_TRUNCATE]
                        host_perms = host_perms[:PERMISSIONS_TRUNCATE]
                    install_type = chromium_install_type_from_meta(meta, manifest)
                    install_source = "policy" if install_type == "policy" else ("webstore" if meta.get("from_webstore") else "normal")
                    results.append({
                        "browser":browser,"user":user,"profile":profile,"id":ext_id,
                        "name": manifest.get("name",""), "version": manifest.get("version",""), "description": manifest.get("description",""),
                        "enabled": bool(enabled), "type":"extension" if not manifest.get("theme") else "theme",
                        "install_type": install_type, "install_source": install_source,
                        "from_webstore": bool(meta.get("from_webstore", False)), "was_installed_by_default": bool(meta.get("was_installed_by_default", False)),
                        "path": meta.get("path",""), "update_url": manifest.get("update_url",""), "homepage_url": manifest.get("homepage_url",""),
                        "install_time_iso": chrome_time_to_iso(meta.get("install_time","")),
                        "permissions": perms, "host_permissions": host_perms,
                        "permissions_count": len(perms), "host_permissions_count": len(host_perms),
                        "permissions_truncated": p_trunc, "host_permissions_truncated": h_trunc,
                        "risk_score": score, "risk_level": level, "risk_reasons": reasons,
                    })
                    seen_ids.add(ext_id)
                except Exception:
                    continue
        results.extend(chromium_fallback_scan_profile(prof_dir, browser, user, profile, seen_ids))
    return results

# --- Firefox collectors ---
def firefox_profiles_for_user(home: str) -> List[Tuple[str,str]]:
    results: List[Tuple[str,str]] = []
    app_sup = os.path.join(home,"Library","Application Support","Firefox")
    profiles_ini = os.path.join(app_sup,"profiles.ini")
    if not os.path.isfile(profiles_ini): return results
    try:
        current: Dict[str,str] = {}
        with open(profiles_ini, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s: continue
                if s.startswith("[") and s.endswith("]"):
                    if "Name" in current and "Path" in current:
                        p = current["Path"]; p_dir = p if p.startswith("/") else os.path.join(app_sup,p)
                        results.append((current["Name"], p_dir))
                    current = {}; continue
                if "=" in s:
                    k,v = s.split("=",1); current[k.strip()] = v.strip()
            if "Name" in current and "Path" in current:
                p = current["Path"]; p_dir = p if p.startswith("/") else os.path.join(app_sup,p)
                results.append((current["Name"], p_dir))
    except Exception as e:
        _log(f"firefox_profiles_for_user parse error: {e}")
    return results

def collect_firefox_for_user(user: str, home: str) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    for prof_name, prof_dir in firefox_profiles_for_user(home):
        try:
            data = safe_read_json(os.path.join(prof_dir,"extensions.json")) or {}
            addons = data.get("addons", [])
            if not isinstance(addons, list): continue
            for a in addons:
                try:
                    if a.get("type") not in ("extension","theme"): continue
                    user_perms = a.get("userPermissions") or {}
                    perms = [str(x) for x in (user_perms.get("permissions") or []) if isinstance(x,str)]
                    origins = [str(x) for x in (user_perms.get("origins") or []) if isinstance(x,str)]
                    score, level, reasons = chromium_risk_from_permissions(perms, origins)
                    p_trunc = len(perms) > PERMISSIONS_TRUNCATE
                    h_trunc = len(origins) > PERMISSIONS_TRUNCATE
                    perms = perms[:PERMISSIONS_TRUNCATE]
                    origins = origins[:PERMISSIONS_TRUNCATE]
                    ext: Dict[str,Any] = {
                        "browser":"firefox","user":user,"profile":prof_name,
                        "id": a.get("id",""), "name": a.get("name",""), "version": a.get("version",""),
                        "description": a.get("description",""),
                        "enabled": bool(a.get("active",False)) and not bool(a.get("userDisabled",False)) and not bool(a.get("appDisabled",False)),
                        "type": a.get("type",""), "signed_state": a.get("signedState", None), "is_system": bool(a.get("isSystem", False)),
                        "is_webextension": bool(a.get("isWebExtension", True)), "path": a.get("path",""),
                        "homepage_url": (a.get("homepageURL") or a.get("homepage_url") or ""),
                        "permissions": perms, "host_permissions": origins,
                        "permissions_count": len(perms), "host_permissions_count": len(origins),
                        "permissions_truncated": p_trunc, "host_permissions_truncated": h_trunc,
                        "risk_score": score, "risk_level": level, "risk_reasons": reasons,
                        "install_type": "system" if a.get("isSystem") else "user",
                        "install_source": "builtin" if a.get("isSystem") else "user",
                    }
                    try:
                        inst = a.get("installDate")
                        if inst is not None:
                            ext["install_time_iso"] = datetime.fromtimestamp(int(inst)/1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        # Some Firefox profiles may have missing or malformed installDate values; ignore and omit install_time_iso.
                        pass
                    try:
                        upd = a.get("updateDate")
                        if upd is not None:
                            ext["update_time_iso"] = datetime.fromtimestamp(int(upd)/1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception: pass
                    results.append(ext)
                except Exception:
                    continue
        except Exception as e:
            _log(f"collect_firefox_for_user error ({user}): {e}")
            continue
    return results

# --- Orchestrator + publish ---
def collect_all(diag: List[Dict[str,str]]) -> Dict[str,Any]:
    all_exts: List[Dict[str,Any]] = []
    counts: Dict[str,int] = {
        "total":0,"safari":0,"chrome":0,"edge":0,"brave":0,"chromium":0,"firefox":0,
        "high_risk":0,"medium_risk":0,"low_risk":0,"policy":0
    }
    users = list_human_user_homes()
    diag.append({"stage":"users","detail":f"{len(users)} user(s) discovered"})
    for user,home in users:
        try: s = collect_safari_for_user(user,home); all_exts.extend(s); counts["safari"] += len(s)
        except Exception as e: diag.append({"stage":"safari","detail":f"{user}: {e}"}); _log(f"safari error ({user}): {traceback.format_exc()}")
        try: c = collect_chromium_for_user(user,home,"chrome",["Google","Chrome"]); all_exts.extend(c); counts["chrome"] += len(c)
        except Exception as e: diag.append({"stage":"chrome","detail":f"{user}: {e}"}); _log(f"chrome error ({user}): {traceback.format_exc()}")
        try: e = collect_chromium_for_user(user,home,"edge",["Microsoft Edge"]); all_exts.extend(e); counts["edge"] += len(e)
        except Exception as e_: diag.append({"stage":"edge","detail":f"{user}: {e_}"}); _log(f"edge error ({user}): {traceback.format_exc()}")
        try: b = collect_chromium_for_user(user,home,"brave",["BraveSoftware","Brave-Browser"]); all_exts.extend(b); counts["brave"] += len(b)
        except Exception as e: diag.append({"stage":"brave","detail":f"{user}: {e}"}); _log(f"brave error ({user}): {traceback.format_exc()}")
        try: cr = collect_chromium_for_user(user,home,"chromium",["Chromium"]); all_exts.extend(cr); counts["chromium"] += len(cr)
        except Exception as e: diag.append({"stage":"chromium","detail":f"{user}: {e}"}); _log(f"chromium error ({user}): {traceback.format_exc()}")
        try: f = collect_firefox_for_user(user,home); all_exts.extend(f); counts["firefox"] += len(f)
        except Exception as e: diag.append({"stage":"firefox","detail":f"{user}: {e}"}); _log(f"firefox error ({user}): {traceback.format_exc()}")
    counts["total"] = counts["safari"]+counts["chrome"]+counts["edge"]+counts["brave"]+counts["chromium"]+counts["firefox"]
    for ext in all_exts:
        level = (ext.get("risk_level") or "low").lower()
        if level in ("low","medium","high"):
            counts[f"{level}_risk"] += 1
        if (ext.get("install_type") or "").lower() in ("policy","system"):
            counts["policy"] += 1
    diag.append({"stage":"summary","detail":f"counts={counts}"})
    return {"extensions": all_exts, "counts": counts}

def publish(submission: Dict[str,Any], inventory: Dict[str,Any], diag: List[Dict[str,str]]) -> None:
    exts: List[Dict[str,Any]] = inventory.get("extensions", [])
    counts: Dict[str,int] = inventory.get("counts", {})
    full_json = json.dumps(inventory, separators=(",",":"))
    truncated = False
    if len(full_json) > RAW_JSON_TRUNCATE:
        full_json = full_json[:RAW_JSON_TRUNCATE] + "...[truncated]"
        truncated = True
    facts_for_ui: Dict[str,str] = {
        "timestamp": _utc_iso(),
        "browser_ext_total": to_string(counts.get("total",0)),
        "browser_ext_safari": to_string(counts.get("safari",0)),
        "browser_ext_chrome": to_string(counts.get("chrome",0)),
        "browser_ext_edge": to_string(counts.get("edge",0)),
        "browser_ext_brave": to_string(counts.get("brave",0)),
        "browser_ext_chromium": to_string(counts.get("chromium",0)),
        "browser_ext_firefox": to_string(counts.get("firefox",0)),
        "browser_ext_policy": to_string(counts.get("policy",0)),
        "browser_ext_risk_high": to_string(counts.get("high_risk",0)),
        "browser_ext_risk_medium": to_string(counts.get("medium_risk",0)),
        "browser_ext_risk_low": to_string(counts.get("low_risk",0)),
        "browser_extensions_json": full_json,
        "active_user_only": to_string(ACTIVE_USER_ONLY),
        "include_chromium_permissions": to_string(INCLUDE_CHROMIUM_PERMISSIONS),
        "permissions_truncate": to_string(PERMISSIONS_TRUNCATE),
        "json_truncated": to_string(truncated),
        "module_sha256": to_string(sha256),
        "module_version": to_string(__version__),
    }
    flattened: Dict[str,str] = {}
    over_limit = False
    for idx, ext in enumerate(exts):
        if idx >= MAX_FLATTENED_EXTENSIONS:
            over_limit = True; break
        browser = normalize_key(ext.get("browser",""))
        user = normalize_key(ext.get("user",""))
        profile = normalize_key(ext.get("profile",""))
        extid = normalize_key(ext.get("id","")) or f"idx{idx}"
        prefix = f"browser_ext_{browser}_{user}_{profile}_{extid}"
        flattened[f"{prefix}_name"] = to_string(ext.get("name",""))
        flattened[f"{prefix}_version"] = to_string(ext.get("version",""))
        flattened[f"{prefix}_enabled"] = to_string(ext.get("enabled",""))
        flattened[f"{prefix}_type"] = to_string(ext.get("type",""))
        flattened[f"{prefix}_path"] = to_string(ext.get("path",""))
        for opt in ("description","install_type","install_source","from_webstore","was_installed_by_default",
                    "update_url","homepage_url","install_time_iso","update_time_iso",
                    "signed_state","is_system","is_webextension","source",
                    "permissions_count","host_permissions_count","permissions_truncated","host_permissions_truncated",
                    "risk_score","risk_level"):
            if ext.get(opt) is not None:
                flattened[f"{prefix}_{normalize_key(opt)}"] = to_string(ext.get(opt))
    for k,v in flattened.items():
        if k not in facts_for_ui:
            facts_for_ui[k] = v
    submission["facts"] = {str(k): to_string(v) for k,v in facts_for_ui.items()}
    submission["extra_data"] = {
        "checkin_module": MODULE_NAME,
        "checkin_module_version": __version__,
        "flattened_capped": "true" if over_limit else "false",
    }
    submission.setdefault("messages", [])
    submission["messages"].append({"message_type":"INFO","text":f"{MODULE_NAME} v{__version__} start {_utc_iso()}"})
    for d in diag[:10]:
        submission["messages"].append({"message_type":"INFO","text":f"{MODULE_NAME} diag: {d}"})
    if counts.get("total",0) == 0:
        submission["messages"].append({"message_type":"WARN","text":f"{MODULE_NAME}: no extensions discovered."})
    if over_limit:
        submission["messages"].append({"message_type":"WARN","text":f"{MODULE_NAME}: flattened capped at {MAX_FLATTENED_EXTENSIONS}."})
    if truncated:
        submission["messages"].append({"message_type":"WARN","text":f"{MODULE_NAME}: browser_extensions_json truncated."})
    submission["messages"].append({"message_type":"INFO","text":f"{MODULE_NAME} finish {_utc_iso()}"})
    try:
        sal.set_checkin_results(MODULE_NAME, submission)
    except Exception as e:
        _log(f"sal.set_checkin_results failed: {e}\n{traceback.format_exc()}")
        # still return gracefully

def main() -> None:
    _log("main() start")
    submission: Dict[str,Any] = {}
    try:
        try:
            submission = sal.get_checkin_results().get(MODULE_NAME, {}) or {}
        except Exception as e:
            _log(f"sal.get_checkin_results failed: {e}\n{traceback.format_exc()}")
            submission = {}
        submission.setdefault("messages", [])
        diag: List[Dict[str,str]] = []
        inv = collect_all(diag)
        _log(f"collect_all done: counts={inv.get('counts')}")
        publish(submission, inv, diag)
        _log("publish done")
    except Exception as e:
        _log(f"FATAL: {e}\n{traceback.format_exc()}")
        try:
            submission["facts"] = {
                "timestamp": _utc_iso(),
                "browser_ext_total":"0","browser_ext_safari":"0","browser_ext_chrome":"0",
                "browser_ext_edge":"0","browser_ext_brave":"0","browser_ext_chromium":"0",
                "browser_ext_firefox":"0","browser_ext_policy":"0",
                "browser_ext_risk_high":"0","browser_ext_risk_medium":"0","browser_ext_risk_low":"0",
                "browser_extensions_json":"{}",
                "module_sha256": to_string(sha256),
                "module_version": to_string(__version__),
            }
            submission.setdefault("messages", [])
            submission["messages"].append({"message_type":"ERROR","text":f"{MODULE_NAME} collector error: {e}"})
            sal.set_checkin_results(MODULE_NAME, submission)
        except Exception as e2:
            _log(f"FATAL during error publish: {e2}\n{traceback.format_exc()}")

if __name__ == "__main__":
    try:
        main()
        print(f"[{MODULE_NAME}] submission prepared at {_utc_iso()}")
    except Exception as e:
        _log(f"UNCAUGHT: {e}\n{traceback.format_exc()}")
