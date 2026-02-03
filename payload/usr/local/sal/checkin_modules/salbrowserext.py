#!/usr/local/sal/Python.framework/Versions/Current/bin/python3
# -*- coding: utf-8 -*-

# Sal checkin module: salbrowserext (diagnostic v1.2.3)
# - Same features as v1.2.2, plus early import-time logging (before 'import sal')
# - Captures Python executable/version, sys.path, and module file SHA256
# - If 'import sal' fails, logs the traceback to module log

import sys, os, hashlib, json, re, plistlib, pwd, subprocess, time, traceback
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Tuple, Optional, Set

__version__ = "1.2.3"
MODULE_NAME = "salbrowserext"
LOG_PATH = "/usr/local/sal/var/log/salbrowserext.log"

def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _log(msg: str) -> None:
    """Write log message with error suppression. Uses unbuffered I/O for crash diagnostics."""
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True, mode=0o755)
        # Create/open log with restrictive permissions
        log_fd = os.open(LOG_PATH, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(log_fd, "a", encoding="utf-8", buffering=1) as f:  # Line buffering
            f.write(f"{_utc_iso()} [{MODULE_NAME}] {msg}\n")
    except Exception:
        pass  # Silent fail - logging should never break the module

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
sal = None  # Initialize to None
SAL_IMPORT_FAILED = False
try:
    import sal  # provided by Sal client env
    _log("import sal OK")
except Exception as e:
    SAL_IMPORT_FAILED = True
    _log(f"CRITICAL SECURITY WARNING: import sal FAILED: {e}\n{traceback.format_exc()}")
    _log("WARNING: Extension data will NOT be submitted to server - security events may be missed!")
    # We can't submit facts without sal, but we continue so at least the submitter logs this file log.
    # Create a minimal mock to prevent NameErrors later
    class _SalMock:
        @staticmethod
        def get_checkin_results():
            return {}
        @staticmethod
        def set_checkin_results(module_name, data):
            _log(f"MOCK (DATA NOT SUBMITTED): Would have submitted {len(str(data))} bytes for {module_name}")
            # Write to stderr so it's visible in system logs
            try:
                sys.stderr.write(f"SECURITY WARNING: {module_name} data not submitted - sal module unavailable\n")
            except Exception:
                pass
    sal = _SalMock()

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
    """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO 8601."""
    try:
        micro = int(str(chrome_time))
        # Validate reasonable range (avoid overflow)
        if micro < 0 or micro > 2**63 - 1:
            return to_string(chrome_time)
        epoch = datetime(1601,1,1,tzinfo=timezone.utc)
        return (epoch + timedelta(microseconds=micro)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return to_string(chrome_time)

def safe_read_json(path: str, max_size: int = 10 * 1024 * 1024) -> Optional[dict]:
    """Safely read and parse JSON file. Returns None on any error.
    
    Args:
        path: Path to JSON file
        max_size: Maximum file size in bytes (default 10MB)
    """
    try:
        # Check file size before reading to prevent DoS
        file_size = os.path.getsize(path)
        if file_size > max_size:
            _log(f"JSON file too large: {path} ({file_size} bytes, max {max_size})")
            return None
        
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            # Basic schema validation - must be dict or list
            if not isinstance(data, (dict, list)):
                _log(f"Invalid JSON structure in {path}: expected dict or list, got {type(data)}")
                return None
            return data
    except (OSError, json.JSONDecodeError, ValueError) as e:
        _log(f"Error reading JSON {path}: {e}")
        return None

def safe_read_plist(path: str, max_size: int = 10 * 1024 * 1024) -> Optional[Any]:
    """Safely read and parse plist file. Returns None on any error.
    
    Args:
        path: Path to plist file
        max_size: Maximum file size in bytes (default 10MB)
    """
    try:
        # Check file size before reading to prevent DoS
        file_size = os.path.getsize(path)
        if file_size > max_size:
            _log(f"Plist file too large: {path} ({file_size} bytes, max {max_size})")
            return None
        
        with open(path, "rb") as f:
            return plistlib.load(f)
    except (OSError, plistlib.InvalidFileException, ValueError) as e:
        _log(f"Error reading plist {path}: {e}")
        return None

def run_stat_console_user() -> Optional[str]:
    """Get console user via stat command. Returns None if root or on error."""
    try:
        result = subprocess.run(
            ["/usr/bin/stat", "-f", "%Su", "/dev/console"],
            capture_output=True,
            text=True,
            timeout=5.0,  # Prevent hanging
            check=True
        )
        out = result.stdout.strip()
        if result.stderr:
            _log(f"stat console user stderr: {result.stderr[:200]}")
        if out and out != "root" and len(out) < 256:  # Sanity check
            return out
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        _log(f"run_stat_console_user error: {e}")
    return None

def get_logged_in_gui_users() -> List[str]:
    """Get all users with active GUI sessions using multiple detection methods.
    
    Returns list of usernames with active GUI sessions, useful when running as root.
    Combines console user, users with WindowServer connections, and logged-in users.
    """
    users: Set[str] = set()
    
    # Method 1: Console user (who owns /dev/console)
    console_user = run_stat_console_user()
    if console_user:
        users.add(console_user)
    
    # Method 2: Users with active loginwindow processes (Fast User Switching)
    try:
        out = subprocess.check_output(
            ["/usr/bin/pgrep", "-x", "loginwindow"],
            text=True,
            timeout=5.0,
            stderr=subprocess.DEVNULL
        ).strip()
        for pid in out.split('\n'):
            if not pid: continue
            try:
                ps_out = subprocess.check_output(
                    ["/bin/ps", "-p", pid, "-o", "user="],
                    text=True,
                    timeout=2.0,
                    stderr=subprocess.DEVNULL
                ).strip()
                if ps_out and ps_out != "root" and len(ps_out) < 256:
                    users.add(ps_out)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                continue
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        pass
    
    # Method 3: Check for users with active WindowServer connections
    try:
        out = subprocess.check_output(
            ["/usr/bin/who"],
            text=True,
            timeout=5.0,
            stderr=subprocess.DEVNULL
        ).strip()
        for line in out.split('\n'):
            if 'console' in line:
                parts = line.split()
                if parts and parts[0] != "root" and len(parts[0]) < 256:
                    users.add(parts[0])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        pass
    
    return sorted(list(users))

def list_human_user_homes() -> List[Tuple[str,str]]:
    """Get list of human user (UID >= 500) home directories.
    
    When ACTIVE_USER_ONLY is True and running as root, detects all users with
    active GUI sessions (including Fast User Switching scenarios).
    """
    try:
        if ACTIVE_USER_ONLY:
            # Get all users with active GUI sessions (handles Fast User Switching)
            gui_users = get_logged_in_gui_users()
            if gui_users:
                _log(f"Detected GUI users: {gui_users}")
                results: List[Tuple[str,str]] = []
                for username in gui_users:
                    try:
                        pwent = pwd.getpwnam(username)
                        if pwent.pw_uid >= 500 and pwent.pw_dir.startswith("/Users/") and os.path.isdir(pwent.pw_dir):
                            results.append((pwent.pw_name, pwent.pw_dir))
                        else:
                            _log(f"GUI user {username} doesn't meet criteria (UID={pwent.pw_uid}, home={pwent.pw_dir})")
                    except KeyError:
                        _log(f"GUI user {username} not found in password database")
                        continue
                if results:
                    return results
                # If no GUI users qualified, fall through to enumerate all users
                _log("No GUI users qualified, falling back to all users")
        
        # Enumerate all human users (UID >= 500)
        users: List[Tuple[str,str]] = []
        for pwent in pwd.getpwall():
            try:
                # Skip system users (UID < 500)
                if pwent.pw_uid < 500: continue
                home = pwent.pw_dir or ""
                if not home.startswith("/Users/"): continue
                if not os.path.isdir(home): continue
                # Validate username is reasonable (prevent injection)
                if len(pwent.pw_name) > 255 or not pwent.pw_name:
                    continue
                # SECURITY: Verify home directory ownership matches user UID
                try:
                    stat_info = os.stat(home)
                    if stat_info.st_uid != pwent.pw_uid:
                        _log(f"Home directory ownership mismatch for {pwent.pw_name}: "
                             f"expected UID {pwent.pw_uid}, got {stat_info.st_uid}")
                        continue
                except OSError as e:
                    _log(f"Cannot stat home directory {home}: {e}")
                    continue
                users.append((pwent.pw_name, home))
            except (AttributeError, OSError):
                continue
        return users
    except Exception as exc:
        _log(f"list_human_user_homes error: {exc}")
        return []

# --- Risk & perms helpers ---
def chromium_permissions_from_manifest(manifest: dict) -> Tuple[List[str], List[str]]:
    """Extract permissions and host permissions from Chromium manifest.
    
    Returns:
        Tuple of (permissions, host_permissions) lists
    """
    if not isinstance(manifest, dict):
        return [], []
    
    perms = manifest.get("permissions") or []
    host_perms = manifest.get("host_permissions") or []
    p = [str(x) for x in perms if isinstance(x, str)]
    h = [str(x) for x in host_perms if isinstance(x, str)]
    p_hosts = [x for x in p if x in BROAD_HOST_PATTERNS or "://" in x or x.endswith("/*")]
    host_all = list(dict.fromkeys(h + p_hosts))  # dict.fromkeys preserves order and deduplicates
    return p, host_all

def chromium_risk_from_permissions(perms: List[str], host_perms: List[str]) -> Tuple[int,str,List[str]]:
    """Calculate risk score (0-10) based on permissions.
    
    Returns:
        Tuple of (score, level, reasons) where level is 'low'/'medium'/'high'
    """
    reasons: List[str] = []
    score = 0
    if any(h in BROAD_HOST_PATTERNS for h in host_perms):
        score += 5
        reasons.append("broad_host_access")
    sens_hits = sorted(set(p for p in perms if p in SENSITIVE_PERMISSIONS))
    if sens_hits:
        score += min(4, len(sens_hits))
        reasons.append("sensitive_perms:" + ",".join(sens_hits[:6]))
    if "nativeMessaging" in perms:
        score += 1
        if not any("nativeMessaging" in r for r in reasons):
            reasons.append("nativeMessaging")
    score = max(0, min(10, score))
    level = "low" if score < 3 else ("medium" if score < 7 else "high")
    return score, level, reasons

def chromium_install_type_from_meta(meta: dict, manifest: dict) -> str:
    """Determine installation type from extension metadata.
    
    Returns:
        One of: 'policy', 'default', 'webstore', 'normal'
    """
    location = meta.get("location")
    if location == 5: return "policy"
    if meta.get("was_installed_by_default"): return "default"
    if meta.get("from_webstore"): return "webstore"
    up = (manifest or {}).get("update_url") or ""
    if "google.com/service/update2/crx" in up or "edge.microsoft.com" in up:
        return "webstore"
    return "normal"

def chromium_is_unpublished(meta: dict, manifest: dict) -> bool:
    """Determine if extension is unpublished/developer mode.
    
    Unpublished extensions are typically:
    - Loaded via developer mode (location 4)
    - Not from web store
    - Sideloaded or manually installed
    
    Returns:
        True if extension appears to be unpublished/developer mode
    """
    location = meta.get("location")
    from_webstore = meta.get("from_webstore", False)
    
    # location 4 = External extension (developer mode/unpacked)
    if location == 4:
        return True
    
    # Not from webstore and no webstore update URL = likely unpublished
    if not from_webstore:
        up = (manifest or {}).get("update_url") or ""
        # If no update URL or non-webstore URL, likely unpublished
        if not up or ("google.com" not in up and "microsoft.com" not in up and "edge.microsoft.com" not in up):
            # Exclude policy and default installs
            if location not in (5, 10) and not meta.get("was_installed_by_default"):
                return True
    
    return False

# --- Safari collectors ---
def collect_safari_plist_for_user(user: str, home: str) -> List[Dict[str, Any]]:
    """Collect Safari extensions from user's plist files.
    
    Checks both containerized and legacy plist locations.
    """
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
                    if not isinstance(item, dict): continue
                    ext_id = item.get("Identifier") or item.get("Bundle Identifier") or item.get("AppIdentifier") or ""
                    # Validate critical fields - skip if no ID
                    if not ext_id or not isinstance(ext_id, str):
                        continue
                    results.append({
                        "browser":"safari","user":user,"profile":"default",
                        "id": ext_id,
                        "name": item.get("Name") or item.get("Bundle Name") or "",
                        "version": item.get("Version") or "",
                        "enabled": bool(item.get("Enabled", False)),
                        "type":"app-extension","path": item.get("Archive File Name") or item.get("Bundle Directory") or "",
                        "source":"plist","install_type":"user",
                    })
                except (AttributeError, TypeError):
                    continue
    except Exception as exc:
        _log(f"collect_safari_plist_for_user error ({user}): {exc}")
    return results

def iter_app_bundles(time_budget: float) -> List[str]:
    """Scan for .app bundles with time limit. Returns list of app paths."""
    apps: List[str] = []
    t0 = time.time()
    for root in ("/Applications","/System/Applications", os.path.expanduser("~/Applications")):
        if time.time() - t0 > time_budget: 
            _log(f"iter_app_bundles: timeout reached at {root}")
            break
        if not os.path.isdir(root): continue
        # Resolve root to prevent symlink attacks
        try:
            root = os.path.realpath(root)
        except OSError:
            continue
        try:
            for name in os.listdir(root):
                if time.time() - t0 > time_budget: break
                # Prevent path traversal attacks
                if ".." in name or "/" in name or name.startswith("."):
                    continue
                if not name.endswith(".app"): continue
                path = os.path.join(root, name)
                # Verify it's actually a directory and not a symlink escape
                if os.path.isdir(path) and not os.path.islink(path):
                    # SECURITY: Ensure resolved path is still under the root directory
                    # Using commonpath instead of startswith to prevent bypass attacks
                    try:
                        realpath = os.path.realpath(path)
                        # Verify paths are on same filesystem and realpath is under root
                        common = os.path.commonpath([realpath, root])
                        if common == root and realpath.startswith(root + os.sep):
                            apps.append(path)
                        else:
                            _log(f"Path traversal attempt detected: {path} -> {realpath} (root: {root})")
                    except (OSError, ValueError) as e:
                        _log(f"Path validation error for {path}: {e}")
                        continue
        except OSError:
            continue
    return apps

def scan_app_for_safari_extensions(app_path: str) -> List[Dict[str,str]]:
    """Scan a .app bundle for Safari extension .appex files."""
    results: List[Dict[str,str]] = []
    plugdir = os.path.join(app_path,"Contents","PlugIns")
    if not os.path.isdir(plugdir): return results
    try:
        for item in os.listdir(plugdir):
            # Security: prevent path traversal
            if ".." in item or "/" in item or item.startswith("."):
                continue
            if not item.endswith(".appex"): continue
            appex = os.path.join(plugdir,item)
            if not os.path.isdir(appex) or os.path.islink(appex): continue
            info = safe_read_plist(os.path.join(appex,"Contents","Info.plist")) or {}
            ext = (info.get("NSExtension") or {})
            ident = ext.get("NSExtensionPointIdentifier","")
            if not isinstance(ident,str) or not ident.startswith("com.apple.Safari."): continue
            if "web-extension" in ident: ext_type="web-extension"
            elif "content-blocker" in ident: ext_type="content-blocker"
            else: ext_type="extension"
            name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or os.path.basename(appex)
            bundle_id = info.get("CFBundleIdentifier","")
            # Validate critical fields - skip if no ID
            if not bundle_id or not isinstance(bundle_id, str):
                _log(f"Skipping Safari extension with no bundle ID: {appex}")
                continue
            results.append({
                "browser":"safari","user":"","profile":"default",
                "id": bundle_id, "name": name,
                "version": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "",
                "enabled":"","type":ext_type,"path":appex,"source":"app-scan","install_type":"app",
            })
    except OSError as exc:
        _log(f"scan_app_for_safari_extensions error ({app_path}): {exc}")
    return results

def collect_safari_for_user(user: str, home: str) -> List[Dict[str, Any]]:
    """Collect all Safari extensions for a user from plists and app bundles."""
    results: List[Dict[str, Any]] = []
    dedup: Set[str] = set()
    for ext in collect_safari_plist_for_user(user, home):
        results.append(ext)
        dedup.add(ext.get("id",""))
    for app in iter_app_bundles(SAFARI_APP_SCAN_TIMEOUT):
        for ext in scan_app_for_safari_extensions(app):
            ext["user"]=user
            ext_id = ext.get("id","")
            if ext_id and ext_id in dedup: continue
            results.append(ext)
            if ext_id: dedup.add(ext_id)
    return results

# --- Chromium collectors ---
def enumerate_chromium_profiles(base_dir: str) -> List[str]:
    """Find all Chromium-based browser profiles in base directory."""
    profiles: List[str] = []
    try:
        for d in os.listdir(base_dir):
            p = os.path.join(base_dir,d)
            if not os.path.isdir(p): continue
            if os.path.isfile(os.path.join(p,"Preferences")) or os.path.isdir(os.path.join(p,"Extensions")):
                profiles.append(d)
    except OSError:
        pass
    return profiles

def chromium_fallback_scan_profile(base_profile: str, browser: str, user: str, profile: str, seen_ids: Set[str]) -> List[Dict[str, Any]]:
    """Fallback: scan Extensions directory when Preferences.json is missing/incomplete."""
    results: List[Dict[str, Any]] = []
    ext_root = os.path.join(base_profile,"Extensions")
    if not os.path.isdir(ext_root): return results
    try:
        for ext_id in os.listdir(ext_root):
            # Security: validate extension ID format and prevent path traversal
            if not ext_id or ".." in ext_id or "/" in ext_id or ext_id.startswith("."):
                continue
            id_dir = os.path.join(ext_root,ext_id)
            if not os.path.isdir(id_dir) or os.path.islink(id_dir) or ext_id in seen_ids:
                continue
            versions = [v for v in os.listdir(id_dir) if os.path.isdir(os.path.join(id_dir,v)) and ".." not in v]
            if not versions: continue
            versions.sort()
            ver = versions[-1]
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
            except (TypeError, ValueError):
                continue
    except OSError as exc:
        _log(f"chromium_fallback_scan_profile error: {exc}")
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
                    is_unpublished = chromium_is_unpublished(meta, manifest)
                    location = meta.get("location")  # Store for reporting
                    results.append({
                        "browser":browser,"user":user,"profile":profile,"id":ext_id,
                        "name": manifest.get("name",""), "version": manifest.get("version",""), "description": manifest.get("description",""),
                        "enabled": bool(enabled), "type":"extension" if not manifest.get("theme") else "theme",
                        "install_type": install_type, "install_source": install_source,
                        "from_webstore": bool(meta.get("from_webstore", False)), "was_installed_by_default": bool(meta.get("was_installed_by_default", False)),
                        "is_unpublished": bool(is_unpublished), "location": location if location is not None else "",
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
        with open(profiles_ini, "r", encoding="utf-8", errors="replace") as f:
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
    """Collect Firefox extension data for a specific user."""
    results: List[Dict[str,Any]] = []
    for prof_name, prof_dir in firefox_profiles_for_user(home):
        try:
            data = safe_read_json(os.path.join(prof_dir,"extensions.json")) or {}
            addons = data.get("addons", [])
            if not isinstance(addons, list): continue
            for a in addons:
                try:
                    if a.get("type") not in ("extension","theme"): continue
                    # Validate critical fields
                    ext_id = a.get("id","")
                    if not ext_id or not isinstance(ext_id, str):
                        continue
                    user_perms = a.get("userPermissions") or {}
                    perms = [str(x) for x in (user_perms.get("permissions") or []) if isinstance(x,str)]
                    origins = [str(x) for x in (user_perms.get("origins") or []) if isinstance(x,str)]
                    score, level, reasons = chromium_risk_from_permissions(perms, origins)
                    p_trunc = len(perms) > PERMISSIONS_TRUNCATE
                    h_trunc = len(origins) > PERMISSIONS_TRUNCATE
                    perms = perms[:PERMISSIONS_TRUNCATE]
                    origins = origins[:PERMISSIONS_TRUNCATE]
                    signed_state = a.get("signedState")
                    # Firefox: signedState 0 = missing/unsigned (developer/unpublished)
                    # signedState 1 = signed, 2 = system addon
                    is_unpublished = signed_state == 0 if signed_state is not None else False
                    
                    ext: Dict[str,Any] = {
                        "browser":"firefox","user":user,"profile":prof_name,
                        "id": a.get("id",""), "name": a.get("name",""), "version": a.get("version",""),
                        "description": a.get("description",""),
                        "enabled": bool(a.get("active",False)) and not bool(a.get("userDisabled",False)) and not bool(a.get("appDisabled",False)),
                        "type": a.get("type",""), "signed_state": signed_state, "is_system": bool(a.get("isSystem", False)),
                        "is_webextension": bool(a.get("isWebExtension", True)), "is_unpublished": bool(is_unpublished),
                        "path": a.get("path",""),
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
                    except Exception: pass
                    try:
                        upd = a.get("updateDate")
                        if upd is not None:
                            ext["update_time_iso"] = datetime.fromtimestamp(int(upd)/1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception: pass
                    results.append(ext)
                except Exception:
                    continue
        except Exception as exc:
            _log(f"collect_firefox_for_user profile error ({user}/{prof_name}): {exc}")
            continue
    return results

# --- Orchestrator + publish ---
def collect_all(diag: List[Dict[str,str]]) -> Dict[str,Any]:
    """Orchestrate collection of all browser extensions across all users.
    
    Returns:
        Dictionary with 'extensions' (list) and 'counts' (dict)
    """
    all_exts: List[Dict[str,Any]] = []
    counts: Dict[str,int] = {
        "total":0,"safari":0,"chrome":0,"edge":0,"brave":0,"chromium":0,"firefox":0,
        "high_risk":0,"medium_risk":0,"low_risk":0,"policy":0,"unpublished":0
    }
    users = list_human_user_homes()
    diag.append({"stage":"users","detail":f"{len(users)} user(s) discovered"})
    
    for user, home in users:
        # Safari
        try:
            safari_exts = collect_safari_for_user(user, home)
            all_exts.extend(safari_exts)
            counts["safari"] += len(safari_exts)
        except Exception as exc:
            diag.append({"stage":"safari","detail":f"{user}: {exc}"})
            _log(f"safari error ({user}): {traceback.format_exc()}")
        
        # Chrome
        try:
            chrome_exts = collect_chromium_for_user(user, home, "chrome", ["Google", "Chrome"])
            all_exts.extend(chrome_exts)
            counts["chrome"] += len(chrome_exts)
        except Exception as exc:
            diag.append({"stage":"chrome","detail":f"{user}: {exc}"})
            _log(f"chrome error ({user}): {traceback.format_exc()}")
        
        # Edge
        try:
            edge_exts = collect_chromium_for_user(user, home, "edge", ["Microsoft Edge"])
            all_exts.extend(edge_exts)
            counts["edge"] += len(edge_exts)
        except Exception as exc:
            diag.append({"stage":"edge","detail":f"{user}: {exc}"})
            _log(f"edge error ({user}): {traceback.format_exc()}")
        
        # Brave
        try:
            brave_exts = collect_chromium_for_user(user, home, "brave", ["BraveSoftware", "Brave-Browser"])
            all_exts.extend(brave_exts)
            counts["brave"] += len(brave_exts)
        except Exception as exc:
            diag.append({"stage":"brave","detail":f"{user}: {exc}"})
            _log(f"brave error ({user}): {traceback.format_exc()}")
        
        # Chromium
        try:
            chromium_exts = collect_chromium_for_user(user, home, "chromium", ["Chromium"])
            all_exts.extend(chromium_exts)
            counts["chromium"] += len(chromium_exts)
        except Exception as exc:
            diag.append({"stage":"chromium","detail":f"{user}: {exc}"})
            _log(f"chromium error ({user}): {traceback.format_exc()}")
        
        # Firefox
        try:
            firefox_exts = collect_firefox_for_user(user, home)
            all_exts.extend(firefox_exts)
            counts["firefox"] += len(firefox_exts)
        except Exception as exc:
            diag.append({"stage":"firefox","detail":f"{user}: {exc}"})
            _log(f"firefox error ({user}): {traceback.format_exc()}")
    
    counts["total"] = counts["safari"]+counts["chrome"]+counts["edge"]+counts["brave"]+counts["chromium"]+counts["firefox"]
    
    # Calculate risk counts and unpublished count
    for ext in all_exts:
        level = (ext.get("risk_level") or "low").lower()
        if level in ("low","medium","high"):
            counts[f"{level}_risk"] += 1
        if (ext.get("install_type") or "").lower() in ("policy","system"):
            counts["policy"] += 1
        if ext.get("is_unpublished"):
            counts["unpublished"] += 1
    
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
        "browser_ext_unpublished": to_string(counts.get("unpublished",0)),
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
    seen_prefixes: Set[str] = set()  # Track for collision detection
    
    for idx, ext in enumerate(exts):
        if idx >= MAX_FLATTENED_EXTENSIONS:
            over_limit = True
            break
        
        browser = normalize_key(ext.get("browser",""))
        user = normalize_key(ext.get("user",""))
        profile = normalize_key(ext.get("profile",""))
        extid = normalize_key(ext.get("id","")) or f"idx{idx}"
        prefix = f"browser_ext_{browser}_{user}_{profile}_{extid}"
        
        # Detect and handle key collisions
        if prefix in seen_prefixes:
            _log(f"Key collision detected for prefix: {prefix}")
            prefix = f"{prefix}_{idx}"
        seen_prefixes.add(prefix)
        
        # Core fields (pre-convert to string once)
        flattened[f"{prefix}_name"] = to_string(ext.get("name",""))
        flattened[f"{prefix}_version"] = to_string(ext.get("version",""))
        flattened[f"{prefix}_enabled"] = to_string(ext.get("enabled",""))
        flattened[f"{prefix}_type"] = to_string(ext.get("type",""))
        flattened[f"{prefix}_path"] = to_string(ext.get("path",""))
        for opt in ("description","install_type","install_source","from_webstore","was_installed_by_default",
                    "is_unpublished","location","update_url","homepage_url","install_time_iso","update_time_iso",
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
    if facts_for_ui.get("json_truncated") == "True":
        submission["messages"].append({"message_type":"WARN","text":f"{MODULE_NAME}: browser_extensions_json truncated."})
    submission["messages"].append({"message_type":"INFO","text":f"{MODULE_NAME} finish {_utc_iso()}"})
    try:
        sal.set_checkin_results(MODULE_NAME, submission)
    except Exception as e:
        _log(f"sal.set_checkin_results failed: {e}\n{traceback.format_exc()}")
        # still return gracefully

def main() -> None:
    """Main entry point for browser extension collection."""
    _log("main() start")
    submission: Dict[str,Any] = {}
    
    # Check if sal module is available
    if sal is None:
        _log("FATAL: sal module not available, cannot proceed")
        return
    
    # SECURITY: Alert if sal import failed - data won't be submitted
    if SAL_IMPORT_FAILED:
        _log("SECURITY ALERT: Operating in mock mode - extension data will NOT be submitted!")
        try:
            sys.stderr.write(f"\n{'='*70}\n")
            sys.stderr.write(f"SECURITY WARNING: {MODULE_NAME} running in MOCK MODE\n")
            sys.stderr.write(f"Extension data will NOT be submitted to server!\n")
            sys.stderr.write(f"Security events may be MISSED. Check {LOG_PATH}\n")
            sys.stderr.write(f"{'='*70}\n\n")
        except Exception:
            pass
    
    try:
        try:
            submission = sal.get_checkin_results().get(MODULE_NAME, {}) or {}
        except Exception as exc:
            _log(f"sal.get_checkin_results failed: {exc}\n{traceback.format_exc()}")
            submission = {}
        submission.setdefault("messages", [])
        diag: List[Dict[str,str]] = []
        inv = collect_all(diag)
        _log(f"collect_all done: counts={inv.get('counts')}")
        publish(submission, inv, diag)
        _log("publish done")
    except Exception as exc:
        _log(f"FATAL: {exc}\n{traceback.format_exc()}")
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
            submission["messages"].append({"message_type":"ERROR","text":f"{MODULE_NAME} collector error: {exc}"})
            sal.set_checkin_results(MODULE_NAME, submission)
        except Exception as exc2:
            _log(f"FATAL during error publish: {exc2}\n{traceback.format_exc()}")

if __name__ == "__main__":
    try:
        main()
        print(f"[{MODULE_NAME}] submission prepared at {_utc_iso()}")
    except Exception as exc:
        _log(f"UNCAUGHT: {exc}\n{traceback.format_exc()}")
        raise  # Re-raise for proper error signaling
