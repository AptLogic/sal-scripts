#!/usr/local/sal/Python.framework/Versions/Current/bin/python3
# -*- coding: utf-8 -*-

# Sal checkin module: salmdatp (Microsoft Defender for Endpoint on macOS)
# - Collects mdatp health (JSON first, plaintext fallback)
# - Runs mdatp connectivity test and summarizes results
# - Sanitizes values (quotes, ' [managed]' suffixes, booleans/ints)
# - Publishes human-readable string facts + compact JSON backups
# - FLATTENS JSON dictionaries into individual facts so they are directly searchable in Sal
# - Submits via sal.set_checkin_results('salmdatp', submission)

import json
import re
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Any
import sal  # provided by Sal client env

__version__ = '1.1.0'
MODULE_NAME = 'salmdatp'
MDATP_BIN = '/usr/local/bin/mdatp'

def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def run_cmd(cmd: List[str]) -> (int, str):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output or ''
    except Exception:
        return 1, ''

def mdatp_available() -> bool:
    rc, _ = run_cmd(['/usr/bin/env', 'bash', '-lc', f'test -x {MDATP_BIN}'])
    return rc == 0

def sanitize_value(s: str) -> Any:
    val = s.strip()
    while len(val) >= 2 and val[0] == ' and val[-1] == ':
        val = val[1:-1].strip()
    if val.endswith(' [managed]'):
        val = val[:-10]
    lower = val.lower()
    if lower == 'true':
        return True
    if lower == 'false':
        return False
    try:
        return int(val)
    except ValueError:
        pass
    if (val.startswith('[') and val.endswith(']')) or (val.startswith('{') and val.endswith('}')):
        try:
            return json.loads(val)
        except Exception:
            pass
    return val

def sanitize_facts(facts: Dict[str, Any]) -> Dict[str, Any]:
    cleaned: Dict[str, Any] = {}
    for k, v in facts.items():
        cleaned[k] = sanitize_value(v) if isinstance(v, str) else v
    for k in (
        'cloud_automatic_sample_submission_consent',
        'network_protection_enforcement_level',
        'behavior_monitoring',
        'tamper_protection',
    ):
        if isinstance(cleaned.get(k), str):
            cleaned[k] = sanitize_value(cleaned[k])
    return cleaned

_key_re = re.compile(r'[^a-zA-Z0-9]+')

def normalize_key(component: str) -> str:
    c = _key_re.sub('_', component).strip('_')
    c = re.sub(r'_+', '_', c)
    return c.lower()

def to_string(v: Any) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, separators=(',', ':'))
    return str(v)

def flatten_to_facts(prefix: str, obj: Any, out: Dict[str, str], max_depth: int = 6, _depth: int = 0) -> None:
    if _depth > max_depth:
        out[normalize_key(prefix)] = to_string(obj)
        return

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_prefix = f'{prefix}_{normalize_key(str(k))}'
            flatten_to_facts(new_prefix, v, out, max_depth, _depth + 1)
    elif isinstance(obj, list):
        for idx, v in enumerate(obj):
            new_prefix = f'{prefix}_{idx}'
            flatten_to_facts(new_prefix, v, out, max_depth, _depth + 1)
    else:
        out[normalize_key(prefix)] = to_string(obj)

def collect_health() -> Dict[str, Any]:
    rc, out = run_cmd([MDATP_BIN, 'health', '-output', 'json'])
    if rc == 0 and out.strip():
        try:
            data = json.loads(out)
            keys = (
                'healthy', 'app_version', 'engine_version', 'edr_client_version',
                'real_time_protection_enabled', 'real_time_protection_available',
                'real_time_protection_subsystem', 'behavior_monitoring',
                'cloud_enabled', 'cloud_automatic_sample_submission_consent',
                'cloud_diagnostic_enabled', 'cloud_pin_certificate_thumbs',
                'passive_mode_enabled', 'definitions_status', 'definitions_version',
                'definitions_updated', 'definitions_updated_minutes_ago',
                'automatic_definition_update_enabled', 'network_events_subsystem',
                'device_control_enforcement_level', 'network_protection_status',
                'network_protection_enforcement_level', 'full_disk_access_enabled',
                'managed_by', 'org_id', 'machine_guid', 'release_ring', 'log_level',
                'licensed', 'health_issues', 'edr_machine_id', 'edr_configuration_version',
                'edr_device_tags', 'edr_group_ids', 'product_expiration',
                'ecs_configuration_ids', 'conflicting_applications', 'tamper_protection',
            )
            facts: Dict[str, Any] = {}
            for k in keys:
                if k in data:
                    facts[k] = data[k]
            facts = sanitize_facts(facts)
            ds = facts.get('definitions_updated')
            if isinstance(ds, str) and ' at ' in ds:
                try:
                    dt = datetime.strptime(ds, '%b %d, %Y at %I:%M:%S %p').replace(tzinfo=timezone.utc)
                    facts['definitions_updated_iso'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                except Exception:
                    pass
            return facts
        except json.JSONDecodeError:
            pass
    rc2, out2 = run_cmd([MDATP_BIN, 'health'])
    text = (out2 or '').strip()
    facts: Dict[str, Any] = {}
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or ':' not in line:
                continue
            key, val = line.split(':', 1)
            k = key.strip().lower().replace(' ', '_')
            facts[k] = sanitize_value(val.strip())
    return facts

def collect_connectivity() -> Dict[str, Any]:
    rc, out = run_cmd([MDATP_BIN, 'connectivity', 'test'])
    output = (out or '')
    endpoints: List[Dict[str, Any]] = []
    ok_count = 0
    fail_count = 0
    for line in output.splitlines():
        s = line.strip()
        if not s.startswith('Testing connection with'):
            continue
        try:
            url = s.split(' ... ')[0].replace('Testing connection with ', '').strip()
        except Exception:
            url = None
        if '[OK]' in s:
            status = 'OK'; ok_count += 1
        elif '[FAILED]' in s:
            status = 'FAILED'; fail_count += 1
        else:
            status = 'UNKNOWN'
        endpoints.append({'url': url, 'status': status})
    summary = {'ok': ok_count, 'failed': fail_count, 'total': ok_count + fail_count}
    return {'summary': summary, 'endpoints': endpoints, 'raw': output[:4000]}

def publish(submission: Dict, health: Dict[str, Any], conn: Dict[str, Any]) -> None:
    health_json = json.dumps(health, separators=(',', ':'))
    conn_json = json.dumps(conn, separators=(',', ':'))

    facts_for_ui: Dict[str, str] = {
        'timestamp': utc_iso(),
        'mdatp_installed': 'true',
        'healthy': str(health.get('healthy', '')),
        'app_version': str(health.get('app_version', '')),
        'engine_version': str(health.get('engine_version', '')),
        'definitions_version': str(health.get('definitions_version', '')),
        'definitions_status': str(health.get('definitions_status', '')),
        'definitions_updated': str(health.get('definitions_updated', '')),
        'real_time_protection_enabled': str(health.get('real_time_protection_enabled', '')),
        'cloud_enabled': str(health.get('cloud_enabled', '')),
        'managed_by': str(health.get('managed_by', '')),
        'org_id': str(health.get('org_id', '')),
        'connectivity_ok': str(conn.get('summary', {}).get('ok', '')),
        'connectivity_failed': str(conn.get('summary', {}).get('failed', '')),
        'connectivity_total': str(conn.get('summary', {}).get('total', '')),
        'mdatp_health_json': health_json,
        'mdatp_connectivity_json': conn_json,
    }

    flattened: Dict[str, str] = {}
    if health:
        flatten_to_facts('mdatp_health', health, flattened)
    if conn:
        flatten_to_facts('mdatp_connectivity', conn, flattened)

    for k, v in flattened.items():
        if k not in facts_for_ui:
            facts_for_ui[k] = v

    submission['facts'] = facts_for_ui
    submission['extra_data'] = {'checkin_module_version': __version__}

    submission.setdefault('messages', [])
    failed = conn.get('summary', {}).get('failed', 0)
    if isinstance(failed, int) and failed > 0:
        submission['messages'].append({
            'message_type': 'WARN', 'text': f'mdatp connectivity test: {failed} endpoint(s) failed'
        })
    sal.set_checkin_results(MODULE_NAME, submission)

def main() -> None:
    submission: Dict = sal.get_checkin_results().get(MODULE_NAME, {}) or {}
    submission.setdefault('messages', [])
    if not mdatp_available():
        submission['facts'] = {
            'timestamp': utc_iso(),
            'mdatp_installed': 'false',
            'healthy': '',
            'app_version': '',
            'engine_version': '',
            'definitions_version': '',
            'definitions_status': '',
            'definitions_updated': '',
            'real_time_protection_enabled': '',
            'cloud_enabled': '',
            'managed_by': '',
            'org_id': '',
            'connectivity_ok': '0',
            'connectivity_failed': '0',
            'connectivity_total': '0',
            'mdatp_health_json': '{}',
            'mdatp_connectivity_json': '{}',
        }
        submission['messages'].append({'message_type': 'ERROR', 'text': f'{MDATP_BIN} not found or not executable'})
        sal.set_checkin_results(MODULE_NAME, submission)
        return

    health: Dict[str, Any] = {}
    conn: Dict[str, Any] = {'summary': {'ok': 0, 'failed': 0, 'total': 0}, 'endpoints': [], 'raw': ''}
    try:
        health = collect_health() or {}
    except Exception as e:
        submission['messages'].append({'message_type': 'ERROR', 'text': f'health collector error: {e}'})
        health = {}
    try:
        conn = collect_connectivity() or conn
    except Exception as e:
        submission['messages'].append({'message_type': 'WARN', 'text': f'connectivity collector warning: {e}'})
    publish(submission, health, conn)

if __name__ == '__main__':
    try:
        main()
        print(f'[{MODULE_NAME}] submission prepared at {utc_iso()}')
    except Exception as e:
        sub: Dict = sal.get_checkin_results().get(MODULE_NAME, {}) or {}
        sub.setdefault('messages', [])
        sub['messages'].append({'message_type': 'ERROR', 'text': f'{MODULE_NAME} fatal: {e}'})
        sub['facts'] = {
            'timestamp': utc_iso(),
            'mdatp_installed': 'unknown',
            'healthy': '',
            'app_version': '',
            'engine_version': '',
            'definitions_version': '',
            'definitions_status': '',
            'definitions_updated': '',
            'real_time_protection_enabled': '',
            'cloud_enabled': '',
            'managed_by': '',
            'org_id': '',
            'connectivity_ok': '0',
            'connectivity_failed': '0',
            'connectivity_total': '0',
            'mdatp_health_json': '{}',
            'mdatp_connectivity_json': '{}',
        }
        sal.set_checkin_results(MODULE_NAME, sub)