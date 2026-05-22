#!/usr/bin/env python3
"""RuleForge - deterministic detection-content converter.

Single-file script that fetches Sigma rules, YARA rules, and IOC feeds from
public sources, converts each item to EaglEye's internal schema, validates
it, and writes results to ./output/.  See BUILD.md for the spec.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import yaml
import requests
try:
    import plyara
    import plyara.utils
except ImportError:
    plyara = None


# ---------------------------------------------------------------------------
#  Paths (module globals so tests can rebind them)
# ---------------------------------------------------------------------------

ROOT = Path.cwd()
OUTPUT = ROOT / "output"
SIGMA_DIR = OUTPUT / "sigma"
YARA_DIR = OUTPUT / "yara"
IOC_DIR = OUTPUT / "iocs"
REJECT_DIR = OUTPUT / "rejected"
STATE_PATH = ROOT / "state.json"
MITRE_CATALOG_PATH = ROOT / "mitre_attack.json"
MITRE_CATALOG_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

DEFAULT_DEDUP_WINDOW = 60
# Default MITRE technique used when a YARA rule's meta has no attack.tNNNN
# tags. Broad enough to be defensible for an "unknown malware sample"
# detection; the operator should review and refine before promotion.
YARA_DEFAULT_MITRE_TECHNIQUE = "T1027"  # Obfuscated Files or Information

# Default auto_action per event_type. Per project owner directive (overrides
# the BUILD.md / rule_schemas.html "auto_action only on severity=critical"
# constraint): every imported rule gets a default response action so the
# converted corpus is actionable out of the box.
#
#   File-related    -> quarantine_file   (FileCreate, FileClose)
#   Network-related -> block_network     (NetConnect, DnsQuery)
#   Process-related -> suspend_process   (everything else)
#
# Operators tune away from these per-rule before promoting from experimental.
SIGMA_AUTO_ACTION_BY_EVENT_TYPE = {
    "ProcessStart": "suspend_process",
    "ProcessStop":  "suspend_process",
    "FileCreate":   "quarantine_file",
    "FileClose":    "quarantine_file",
    "RegSet":       "suspend_process",
    "RegDelete":    "suspend_process",
    "NetConnect":   "block_network",
    "DnsQuery":     "block_network",
    "ImageLoad":    "suspend_process",
}
YARA_DEFAULT_AUTO_ACTION = "quarantine_file"

ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _verify_setting() -> bool:
    """Return ``verify`` arg for requests — False when the user has opted out.

    Honored controls (preferred → fallback):
      1. ``REQUESTS_CA_BUNDLE`` env var (set by requests automatically) — best
         option for corporate-proxy environments with a known root CA.
      2. ``RULEFORGE_INSECURE=1`` env var — disables TLS verification.
      3. ``--insecure`` CLI flag (sets ``RULEFORGE_INSECURE=1`` in-process).
    """
    return os.environ.get("RULEFORGE_INSECURE", "").lower() not in ("1", "true", "yes")


def _suppress_insecure_warning_once() -> None:
    if not _verify_setting():
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass


def _req_get(url, **kwargs):
    kwargs.setdefault("verify", _verify_setting())
    kwargs.setdefault("timeout", 60)
    _suppress_insecure_warning_once()
    return requests.get(url, **kwargs)


def _req_post(url, **kwargs):
    kwargs.setdefault("verify", _verify_setting())
    kwargs.setdefault("timeout", 60)
    _suppress_insecure_warning_once()
    return requests.post(url, **kwargs)


# ---------------------------------------------------------------------------
#  MITRE reference data
# ---------------------------------------------------------------------------

MITRE_TACTICS: dict[str, str] = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}
TACTIC_NAME_TO_ID: dict[str, str] = {v: k for k, v in MITRE_TACTICS.items()}

# technique_id -> (human_name, primary_tactic_id)
MITRE_TECHNIQUES_BUILTIN: dict[str, tuple[str, str]] = {
    "T1003":     ("OS Credential Dumping", "TA0006"),
    "T1003.001": ("LSASS Memory", "TA0006"),
    "T1003.002": ("Security Account Manager", "TA0006"),
    "T1003.003": ("NTDS", "TA0006"),
    "T1027":     ("Obfuscated Files or Information", "TA0005"),
    "T1036":     ("Masquerading", "TA0005"),
    "T1041":     ("Exfiltration Over C2 Channel", "TA0010"),
    "T1047":     ("Windows Management Instrumentation", "TA0002"),
    "T1053":     ("Scheduled Task/Job", "TA0003"),
    "T1053.005": ("Scheduled Task", "TA0003"),
    "T1055":     ("Process Injection", "TA0005"),
    "T1057":     ("Process Discovery", "TA0007"),
    "T1059":     ("Command and Scripting Interpreter", "TA0002"),
    "T1059.001": ("PowerShell", "TA0002"),
    "T1059.003": ("Windows Command Shell", "TA0002"),
    "T1059.005": ("Visual Basic", "TA0002"),
    "T1068":     ("Exploitation for Privilege Escalation", "TA0004"),
    "T1070":     ("Indicator Removal", "TA0005"),
    "T1070.004": ("File Deletion", "TA0005"),
    "T1071":     ("Application Layer Protocol", "TA0011"),
    "T1078":     ("Valid Accounts", "TA0003"),
    "T1078.004": ("Cloud Accounts", "TA0003"),
    "T1082":     ("System Information Discovery", "TA0007"),
    "T1083":     ("File and Directory Discovery", "TA0007"),
    "T1087":     ("Account Discovery", "TA0007"),
    "T1090":     ("Proxy", "TA0011"),
    "T1098":     ("Account Manipulation", "TA0003"),
    "T1105":     ("Ingress Tool Transfer", "TA0011"),
    "T1112":     ("Modify Registry", "TA0005"),
    "T1133":     ("External Remote Services", "TA0001"),
    "T1134":     ("Access Token Manipulation", "TA0005"),
    "T1140":     ("Deobfuscate/Decode Files or Information", "TA0005"),
    "T1190":     ("Exploit Public-Facing Application", "TA0001"),
    "T1203":     ("Exploitation for Client Execution", "TA0002"),
    "T1204":     ("User Execution", "TA0002"),
    "T1204.002": ("Malicious File", "TA0002"),
    "T1210":     ("Exploitation of Remote Services", "TA0008"),
    "T1218":     ("System Binary Proxy Execution", "TA0005"),
    "T1218.011": ("Rundll32", "TA0005"),
    "T1486":     ("Data Encrypted for Impact", "TA0040"),
    "T1490":     ("Inhibit System Recovery", "TA0040"),
    "T1543":     ("Create or Modify System Process", "TA0003"),
    "T1543.003": ("Windows Service", "TA0003"),
    "T1546":     ("Event Triggered Execution", "TA0003"),
    "T1547":     ("Boot or Logon Autostart Execution", "TA0003"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "TA0003"),
    "T1548":     ("Abuse Elevation Control Mechanism", "TA0004"),
    "T1548.002": ("Bypass User Account Control", "TA0004"),
    "T1555":     ("Credentials from Password Stores", "TA0006"),
    "T1562":     ("Impair Defenses", "TA0005"),
    "T1562.001": ("Disable or Modify Tools", "TA0005"),
    "T1566":     ("Phishing", "TA0001"),
    "T1566.001": ("Spearphishing Attachment", "TA0001"),
    "T1569":     ("System Services", "TA0002"),
    "T1569.002": ("Service Execution", "TA0002"),
    "T1574":     ("Hijack Execution Flow", "TA0003"),
    "T1620":     ("Reflective Code Loading", "TA0005"),
}


def load_mitre_catalog() -> dict[str, tuple[str, str]]:
    catalog = dict(MITRE_TECHNIQUES_BUILTIN)
    if MITRE_CATALOG_PATH.exists():
        try:
            data = json.loads(MITRE_CATALOG_PATH.read_text(encoding="utf-8"))
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                tech_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break
                if not tech_id:
                    continue
                name = obj.get("name", tech_id)
                tactic_id = "TA0002"
                for phase in obj.get("kill_chain_phases", []):
                    pname = phase.get("phase_name", "")
                    if pname in TACTIC_NAME_TO_ID:
                        tactic_id = TACTIC_NAME_TO_ID[pname]
                        break
                catalog.setdefault(tech_id, (name, tactic_id))
        except Exception as exc:
            print(f"[WARN] failed to parse cached MITRE catalog: {exc}")
    return catalog


def fetch_mitre_catalog_if_stale(state: dict, force: bool = False) -> None:
    last = state.get("mitre_catalog_fetched")
    if last and not force and MITRE_CATALOG_PATH.exists():
        try:
            ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) - ts < timedelta(days=7):
                return
        except Exception:
            pass
    print(f"[INFO] fetching MITRE catalog from {MITRE_CATALOG_URL} ...")
    try:
        r = _req_get(MITRE_CATALOG_URL)
        r.raise_for_status()
        MITRE_CATALOG_PATH.write_bytes(r.content)
        state["mitre_catalog_fetched"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_state(state)
        print(f"[INFO] cached MITRE catalog to {MITRE_CATALOG_PATH}")
    except Exception as exc:
        print(f"[WARN] could not fetch MITRE catalog ({exc}). Falling back to built-in set.")


# ---------------------------------------------------------------------------
#  State
# ---------------------------------------------------------------------------

def default_state() -> dict:
    return {
        "next_sigma_id": 1,
        "next_yara_id": 1,
        "next_ioc_id": 1,
        "seen_hashes": {
            "rules": [],
            "malware_bazaar": [],
            "threatfox": [],
            "urlhaus": [],
            "cisa_kev": [],
        },
        "ingest_watermarks": {},
        "mitre_catalog_fetched": None,
    }


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"[WARN] could not read state.json ({exc}); using defaults.")
    return default_state()


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def next_id(state: dict, kind: str) -> str:
    key = {"sigma": "next_sigma_id", "yara": "next_yara_id", "ioc": "next_ioc_id"}[kind]
    n = state[key]
    state[key] = n + 1
    prefix = {"sigma": "R", "yara": "Y", "ioc": "S"}[kind]
    return f"{prefix}-{n:03d}"


# ---------------------------------------------------------------------------
#  Issue + validator
# ---------------------------------------------------------------------------

ERROR = "ERROR"
WARN = "WARN"


@dataclass
class Issue:
    severity: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.code}: {self.message}"


UNIVERSAL_REQUIRED = ["id", "title", "status", "description", "severity", "mitre", "author", "date"]
SEVERITY_ENUM = {"critical", "high", "medium", "low"}
STATUS_ENUM = {"experimental", "test", "stable"}
EVENT_TYPES = {"ProcessStart", "ProcessStop", "FileCreate", "FileClose", "RegSet",
               "RegDelete", "NetConnect", "DnsQuery", "ImageLoad"}
ALLOWED_MODIFIERS = {"exact", "contains", "startswith", "endswith", "re",
                     "gte", "lte", "gt", "lt", "any", "all"}

# Enum-typed NormalizedEvent fields retain PascalCase per RULE_AUTHORING.md §3:
# strings are lowercased at the boundary but enum fields keep their canonical form
# (Created / Outbound / Tcp / System / RegSz / ...).
SIGMA_ENUM_FIELDS = {
    "file_action", "direction", "protocol", "reg_value_type",
    "query_type", "integrity_level", "via",
}

SIGMA_FIELDS_BY_EVENT_TYPE = {
    "ProcessStart": {"process_name", "image_path", "command_line", "parent_name",
                     "parent_image_path", "parent_command_line", "integrity_level",
                     "image_signed", "image_signer", "user_name"},
    "ProcessStop": {"process_name", "image_path", "exit_code", "pid"},
    "FileCreate": {"process_name", "image_path", "target_path", "target_extension", "file_action"},
    "FileClose": {"process_name", "image_path", "target_path", "target_extension",
                  "file_action", "file_size"},
    "RegSet": {"process_name", "image_path", "reg_key", "reg_value_name",
               "reg_value_type", "reg_value_data"},
    "RegDelete": {"process_name", "image_path", "reg_key", "reg_value_name"},
    "NetConnect": {"process_name", "image_path", "protocol", "direction",
                   "src_ip", "src_port", "dst_ip", "dst_port", "dst_hostname", "owning_pid"},
    "DnsQuery": {"process_name", "image_path", "query_name", "query_type",
                 "query_length", "query_entropy", "response_ips", "rcode", "via"},
    "ImageLoad": {"process_name", "image_path", "module_path", "module_size",
                  "image_signed", "image_signer"},
}

# Field -> family taxonomy for the AND-trap filter heuristic.  A single
# filter map that mixes fields from >=3 families almost certainly cannot
# all be true at once, which means the filter suppresses nothing.
SIGMA_FIELD_FAMILIES = {
    "process_name": "process", "image_path": "process", "command_line": "process",
    "parent_name": "parent", "parent_image_path": "parent", "parent_command_line": "parent",
    "image_signed": "signing", "image_signer": "signing",
    "target_path": "file", "target_extension": "file", "file_action": "file",
    "file_size": "file", "old_path": "file",
    "reg_key": "registry", "reg_value_name": "registry",
    "reg_value_type": "registry", "reg_value_data": "registry",
    "protocol": "network", "direction": "network",
    "src_ip": "network", "src_port": "network",
    "dst_ip": "network", "dst_port": "network",
    "dst_hostname": "network", "owning_pid": "network",
    "query_name": "dns", "query_type": "dns", "query_length": "dns",
    "query_entropy": "dns", "response_ips": "dns", "rcode": "dns", "via": "dns",
    "module_path": "module", "module_size": "module",
    "user_name": "identity", "integrity_level": "identity",
}


def _strip_modifiers(key: str) -> tuple[str, list[str]]:
    if "|" not in key:
        return key, []
    parts = key.split("|")
    return parts[0], parts[1:]


def _ensure_list(v) -> list:
    """Coerce values that *should* be a list but might be scalars/None.

    Real-world Sigma sometimes ships ``tags: attack.t1059`` (string) instead
    of a list. We accept either form rather than crashing on iteration.
    """
    if v is None:
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, tuple):
        return list(v)
    return [v]


def _iter_sigma_blocks(rule: dict):
    """Yield (name, block_dict) for every selection/filter map in the rule.

    Handles every valid shape:
      - single ``selection`` map
      - ``selection`` as a list of maps (OR'd alternatives)
      - named ``selection_*`` groups whose values are maps or lists of maps
      - ``filter`` as a single map (Shape A) or list-of-maps (Shape B)
    """
    sel = rule.get("selection")
    if isinstance(sel, dict):
        is_named_groups = bool(sel) and all(
            isinstance(v, (dict, list)) for v in sel.values()
        ) and all(isinstance(k, str) and k.startswith("selection_") for k in sel.keys())
        if is_named_groups:
            for k, v in sel.items():
                if isinstance(v, dict):
                    yield k, v
                elif isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, dict):
                            yield f"{k}[{i}]", item
        else:
            yield "selection", sel
    elif isinstance(sel, list):
        for i, item in enumerate(sel):
            if isinstance(item, dict):
                yield f"selection[{i}]", item
    f = rule.get("filter")
    if isinstance(f, dict):
        yield "filter", f
    elif isinstance(f, list):
        for i, item in enumerate(f):
            if isinstance(item, dict):
                yield f"filter[{i}]", item


def check_universal_fields_present(rule: dict) -> list[Issue]:
    issues = []
    for f in UNIVERSAL_REQUIRED:
        if f not in rule or rule[f] in (None, "", []):
            issues.append(Issue(ERROR, "missing_field", f"Required field '{f}' is missing or empty"))
    return issues


def check_id_format(rule: dict, kind: str) -> list[Issue]:
    rid = rule.get("id", "")
    if kind == "sigma" and not re.fullmatch(r"R-\d{3,}", str(rid)):
        return [Issue(ERROR, "bad_id_format", f"Sigma id must match R-NNN, got: {rid!r}")]
    if kind == "yara" and not re.fullmatch(r"Y-\d{3,}", str(rid)):
        return [Issue(ERROR, "bad_id_format", f"YARA id must match Y-NNN, got: {rid!r}")]
    return []


def check_status_enum(rule: dict) -> list[Issue]:
    if rule.get("status") not in STATUS_ENUM:
        return [Issue(ERROR, "bad_status", f"status must be in {sorted(STATUS_ENUM)}, got {rule.get('status')!r}")]
    return []


def check_severity_enum(rule: dict) -> list[Issue]:
    if rule.get("severity") not in SEVERITY_ENUM:
        return [Issue(ERROR, "bad_severity", f"severity must be in {sorted(SEVERITY_ENUM)}, got {rule.get('severity')!r}")]
    return []


def check_description_min_sentences(rule: dict) -> list[Issue]:
    desc = rule.get("description") or ""
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", desc.strip()) if s.strip()]
    if len(sentences) < 3:
        return [Issue(ERROR, "desc_too_short", f"description must contain >=3 sentences, got {len(sentences)}")]
    return []


def check_mitre_block_complete(rule: dict) -> list[Issue]:
    m = rule.get("mitre")
    if not isinstance(m, dict):
        return [Issue(ERROR, "mitre_missing", "mitre block missing or not a dict")]
    primary = m.get("primary")
    if not isinstance(primary, dict):
        return [Issue(ERROR, "mitre_primary_missing", "mitre.primary is required")]
    needed = ("tactic_id", "tactic", "technique_id", "technique")
    issues = []
    for f in needed:
        if not primary.get(f):
            issues.append(Issue(ERROR, "mitre_primary_incomplete", f"mitre.primary.{f} missing"))
    for sub in m.get("secondary", []) or []:
        if not isinstance(sub, dict):
            issues.append(Issue(ERROR, "mitre_secondary_bad", "mitre.secondary entry not a dict"))
            continue
        for f in needed:
            if not sub.get(f):
                issues.append(Issue(ERROR, "mitre_secondary_incomplete", f"mitre.secondary[].{f} missing"))
    return issues


def check_mitre_techniques_exist_in_catalog(rule: dict, catalog: dict) -> list[Issue]:
    issues = []
    m = rule.get("mitre") or {}
    primary = m.get("primary") or {}
    pid = primary.get("technique_id")
    if pid and pid not in catalog:
        issues.append(Issue(WARN, "mitre_technique_unknown",
                            f"primary technique {pid} not in MITRE catalog"))
    for sub in m.get("secondary", []) or []:
        sid = sub.get("technique_id")
        if sid and sid not in catalog:
            issues.append(Issue(WARN, "mitre_technique_unknown",
                                f"secondary technique {sid} not in MITRE catalog"))
    return issues


def check_author_format(rule: dict) -> list[Issue]:
    a = rule.get("author") or ""
    if not isinstance(a, str) or not a.startswith("ruleforge-converter (source: ") or not a.endswith(")"):
        return [Issue(ERROR, "bad_author", "author must be 'ruleforge-converter (source: <name>)'")]
    return []


def check_date_iso(rule: dict) -> list[Issue]:
    d = rule.get("date") or ""
    if not ISO_DATE_RE.fullmatch(str(d)):
        return [Issue(ERROR, "bad_date", f"date must be YYYY-MM-DD, got {d!r}")]
    return []


def check_sigma_event_type_enum(rule: dict) -> list[Issue]:
    et = rule.get("event_type")
    if et not in EVENT_TYPES:
        return [Issue(ERROR, "bad_event_type", f"event_type invalid, got {et!r}")]
    return []


def check_sigma_selection_not_empty(rule: dict) -> list[Issue]:
    sel = rule.get("selection")
    if not sel:
        return [Issue(ERROR, "empty_selection", "selection is empty")]
    return []


def check_sigma_fields_valid_for_event_type(rule: dict) -> list[Issue]:
    et = rule.get("event_type")
    allowed = SIGMA_FIELDS_BY_EVENT_TYPE.get(et, set())
    issues: list[Issue] = []
    for _, b in _iter_sigma_blocks(rule):
        for key in b.keys():
            field, _mods = _strip_modifiers(key)
            if field not in allowed:
                issues.append(Issue(ERROR, "unmapped_field",
                                    f"field {field!r} not valid for event_type {et}"))
    return issues


def check_sigma_modifiers_in_allowlist(rule: dict) -> list[Issue]:
    issues: list[Issue] = []
    for _, b in _iter_sigma_blocks(rule):
        for key in b.keys():
            _, mods = _strip_modifiers(key)
            for m in mods:
                if m not in ALLOWED_MODIFIERS:
                    issues.append(Issue(ERROR, "bad_modifier", f"modifier {m!r} not allowed"))
    return issues


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for v in value:
            yield from _walk_strings(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk_strings(v)


def check_sigma_string_literals_lowercase(rule: dict) -> list[Issue]:
    issues: list[Issue] = []
    for _, b in _iter_sigma_blocks(rule):
        for key, val in b.items():
            field, mods = _strip_modifiers(key)
            # Regex literals and enum-typed fields are exempt per RULE_AUTHORING.md §3.
            if "re" in mods or field in SIGMA_ENUM_FIELDS:
                continue
            for s in _walk_strings(val):
                if s != s.lower():
                    issues.append(Issue(ERROR, "not_lowercase",
                                        f"value {s!r} under {key!r} must be lowercase"))
    return issues


def check_sigma_regex_safe(rule: dict) -> list[Issue]:
    issues: list[Issue] = []
    for _, b in _iter_sigma_blocks(rule):
        for key, val in b.items():
            _, mods = _strip_modifiers(key)
            if "re" not in mods:
                continue
            for s in _walk_strings(val):
                if len(s) > 1024 and "^" not in s and "$" not in s:
                    issues.append(Issue(ERROR, "unsafe_regex", "regex >1024 chars without anchors"))
                try:
                    re.compile(s)
                except re.error as exc:
                    issues.append(Issue(ERROR, "bad_regex", f"regex {s!r} does not compile: {exc}"))
    return issues


def check_sigma_filter_and_trap(rule: dict) -> list[Issue]:
    """Warn when a single filter map mixes fields from >=3 families.

    Per RULE_AUTHORING.md §4 ("Filter conventions"): combining unrelated
    field families inside one AND-map yields a condition that can never
    all be true at once - the filter then suppresses nothing.  Authors
    should split such filters into a list-of-maps (Shape B).
    """
    issues: list[Issue] = []
    f = rule.get("filter")
    maps: list[dict] = []
    if isinstance(f, dict):
        maps = [f]
    elif isinstance(f, list):
        maps = [item for item in f if isinstance(item, dict)]
    for m in maps:
        families: set[str] = set()
        for key in m.keys():
            field, _ = _strip_modifiers(key)
            fam = SIGMA_FIELD_FAMILIES.get(field)
            if fam:
                families.add(fam)
        if len(families) >= 3:
            issues.append(Issue(WARN, "filter_and_trap",
                                f"filter map spans {len(families)} field families "
                                f"({sorted(families)}) - likely never matches; "
                                "split into a list of maps"))
    return issues


def check_sigma_auto_action_only_if_critical(rule: dict) -> list[Issue]:
    """Per rule_schemas.html §overview, auto_action is "only valid on
    severity=critical." Per project owner override (see DECISIONS.md),
    RuleForge injects auto_action on every imported rule by default. This
    check is therefore a WARN, not an ERROR: it flags the spec divergence
    so operators can promote critical-tier rules first and tune the rest.
    """
    if "auto_action" in rule and rule.get("severity") != "critical":
        return [Issue(WARN, "auto_action_non_critical",
                      f"auto_action={rule['auto_action']!r} set on severity={rule.get('severity')!r} "
                      "(spec normally requires severity=critical)")]
    return []


def check_mitre_tactic_consistency(rule: dict) -> list[Issue]:
    """Per rule_schemas.html §mitre: tactic name must match tactic_id."""
    issues: list[Issue] = []
    m = rule.get("mitre") or {}
    entries: list[tuple[str, dict]] = []
    if isinstance(m.get("primary"), dict):
        entries.append(("primary", m["primary"]))
    for i, sub in enumerate(m.get("secondary", []) or []):
        if isinstance(sub, dict):
            entries.append((f"secondary[{i}]", sub))
    for label, e in entries:
        tid = e.get("tactic_id")
        tname = e.get("tactic")
        if tid and tname and tid in MITRE_TACTICS:
            expected = MITRE_TACTICS[tid]
            if tname != expected:
                issues.append(Issue(ERROR, "mitre_tactic_mismatch",
                                    f"mitre.{label}: tactic={tname!r} does not match "
                                    f"tactic_id={tid} (expected {expected!r})"))
    return issues


# ---- YARA validator ----

YARA_REQUIRED_META = {"id", "family", "description", "author", "date", "severity", "mitre"}
YARA_DISALLOWED_MODULES = {"cuckoo", "elf", "magic"}
SINGLE_STRING_RE = re.compile(r"^\$[A-Za-z0-9_]+$")


def _yara_meta_dict(parsed: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for entry in parsed.get("metadata", []) or []:
        if isinstance(entry, dict):
            for k, v in entry.items():
                out[k.lower()] = v
    return out


def check_yara_meta_keys_present(parsed: dict) -> list[Issue]:
    meta = _yara_meta_dict(parsed)
    issues = []
    for k in YARA_REQUIRED_META:
        if k not in meta or meta[k] in (None, ""):
            issues.append(Issue(ERROR, "yara_meta_missing", f"required meta key '{k}' missing"))
    return issues


def check_yara_structural_anchor_present(parsed: dict, raw_text: str) -> list[Issue]:
    cond = " ".join(parsed.get("condition_terms") or [])
    if any(x in cond for x in ("uint16(0)", "uint32(0)", "filesize")):
        return []
    # plyara tokenizes — try a raw-text fallback too
    if any(x in raw_text for x in ("uint16(0)", "uint32(0)", "filesize")):
        return []
    return [Issue(ERROR, "yara_no_structural_anchor",
                  "condition lacks PE/ELF magic check or filesize gate")]


def check_yara_filesize_cap_present(parsed: dict) -> list[Issue]:
    cond = " ".join(parsed.get("condition_terms") or [])
    if "filesize" in cond:
        return []
    return [Issue(WARN, "yara_filesize_missing", "no filesize cap (will be auto-injected)")]


def check_yara_pe_anchor_preferred(parsed: dict, raw_text: str) -> list[Issue]:
    """WARN when the rule has filesize but no PE/ELF magic.

    A filesize cap alone is sufficient to bound scan time, but a rule
    without an MZ/ELF gate will run its string matchers across every file
    under the cap (text logs, JSON, images, ...). That's correct but noisy.
    """
    cond = " ".join(parsed.get("condition_terms") or [])
    if any(x in cond for x in ("uint16(0)", "uint32(0)")):
        return []
    if any(x in raw_text for x in ("uint16(0)", "uint32(0)")):
        return []
    return [Issue(WARN, "yara_no_pe_anchor",
                  "no PE/ELF magic anchor — rule scans every file under the filesize cap")]


def check_yara_no_single_string_condition(parsed: dict) -> list[Issue]:
    terms = parsed.get("condition_terms") or []
    cond = " ".join(terms).strip()
    if SINGLE_STRING_RE.fullmatch(cond) or cond == "1 of them":
        return [Issue(ERROR, "yara_single_string", "condition is a single-string match")]
    return []


def check_yara_no_disallowed_modules(parsed: dict, raw_text: str) -> list[Issue]:
    issues = []
    for mod in YARA_DISALLOWED_MODULES:
        if re.search(rf'\bimport\s+"{mod}"', raw_text) or re.search(rf"\b{mod}\.", raw_text):
            issues.append(Issue(ERROR, "yara_disallowed_module", f"module {mod!r} disallowed"))
    return issues


def check_yara_compiles(raw_text: str) -> list[Issue]:
    if plyara is None:
        return []
    try:
        plyara.Plyara().parse_string(raw_text)
    except Exception as exc:
        return [Issue(ERROR, "yara_parse_error", f"plyara could not parse: {exc}")]
    return []


# ---- Validator dispatchers ----

def validate_sigma(rule: dict, catalog: dict) -> list[Issue]:
    issues = []
    issues += check_universal_fields_present(rule)
    issues += check_id_format(rule, "sigma")
    issues += check_status_enum(rule)
    issues += check_severity_enum(rule)
    issues += check_description_min_sentences(rule)
    issues += check_mitre_block_complete(rule)
    issues += check_mitre_tactic_consistency(rule)
    issues += check_mitre_techniques_exist_in_catalog(rule, catalog)
    issues += check_author_format(rule)
    issues += check_date_iso(rule)
    issues += check_sigma_event_type_enum(rule)
    issues += check_sigma_selection_not_empty(rule)
    issues += check_sigma_fields_valid_for_event_type(rule)
    issues += check_sigma_modifiers_in_allowlist(rule)
    issues += check_sigma_string_literals_lowercase(rule)
    issues += check_sigma_regex_safe(rule)
    issues += check_sigma_filter_and_trap(rule)
    issues += check_sigma_auto_action_only_if_critical(rule)
    return issues


def validate_yara(path_or_text, catalog: dict) -> list[Issue]:
    if isinstance(path_or_text, (str, Path)) and Path(path_or_text).exists():
        raw_text = Path(path_or_text).read_text(encoding="utf-8")
    else:
        raw_text = str(path_or_text)
    if plyara is None:
        return [Issue(ERROR, "no_plyara", "plyara not installed")]
    try:
        parsed_list = plyara.Plyara().parse_string(raw_text)
    except Exception as exc:
        return [Issue(ERROR, "yara_parse_error", str(exc))]
    if not parsed_list:
        return [Issue(ERROR, "yara_parse_error", "no rules found")]
    parsed = parsed_list[0]
    issues: list[Issue] = []
    issues += check_yara_meta_keys_present(parsed)
    issues += check_yara_structural_anchor_present(parsed, raw_text)
    issues += check_yara_filesize_cap_present(parsed)
    issues += check_yara_pe_anchor_preferred(parsed, raw_text)
    issues += check_yara_no_single_string_condition(parsed)
    issues += check_yara_no_disallowed_modules(parsed, raw_text)
    issues += check_yara_compiles(raw_text)
    meta = _yara_meta_dict(parsed)
    mitre_str = str(meta.get("mitre", "") or "")
    tech_ids = [t.strip() for t in mitre_str.split(",") if t.strip()]
    for tid in tech_ids:
        if tid not in catalog:
            issues.append(Issue(WARN, "mitre_technique_unknown",
                                f"YARA mitre technique {tid} not in catalog"))
    return issues


# ---------------------------------------------------------------------------
#  Sigma converter
# ---------------------------------------------------------------------------

# PascalCase enum values per RULE_AUTHORING.md §3 ("Enum-typed fields keep
# their PascalCase form").  Lowercase here was a bug: downstream rule
# matchers compare to NormalizedEvent.file_action which is PascalCase.
LOGSOURCE_TO_EVENT_TYPE = {
    ("windows", "process_creation"): "ProcessStart",
    ("windows", "process_termination"): "ProcessStop",
    ("windows", "file_event"): ("FileCreate", {"file_action": "Created"}),
    ("windows", "file_change"): ("FileClose", {"file_action": "Modified"}),
    ("windows", "file_delete"): ("FileClose", {"file_action": "Deleted"}),
    ("windows", "registry_set"): "RegSet",
    ("windows", "registry_event"): "RegSet",
    ("windows", "registry_delete"): "RegDelete",
    ("windows", "network_connection"): "NetConnect",
    ("windows", "dns_query"): "DnsQuery",
    ("windows", "image_load"): "ImageLoad",
}

# upstream field name (lower-cased) -> EaglEye name (None = drop)
# Drop-list covers PE-metadata fields that NormalizedEvent doesn't carry
# (the agent normalizes from sysmon but doesn't expose PE resource strings).
SIGMA_FIELD_MAP = {
    "image": "image_path",
    "originalfilename": None,
    "commandline": "command_line",
    "parentimage": "parent_image_path",
    "parentcommandline": "parent_command_line",
    "hashes": None,
    "user": "user_name",
    "integritylevel": "integrity_level",
    "signed": "image_signed",
    "signature": "image_signer",
    "targetfilename": "target_path",
    "targetobject": "reg_key",
    "details": "reg_value_data",
    "destinationip": "dst_ip",
    "destinationport": "dst_port",
    "destinationhostname": "dst_hostname",
    "queryname": "query_name",
    "querytype": "query_type",
    "imageloaded": "module_path",
    "processname": "process_name",
    "parentprocessname": "parent_name",
    # PE-metadata fields — present in many SigmaHQ rules; EaglEye drops them.
    "description": None,
    "product": None,
    "company": None,
    "fileversion": None,
    "md5": None, "sha1": None, "sha256": None, "imphash": None,
    # Rule-management fields surfaced by some upstream variants — ignore.
    "eventid": None, "channel": None, "provider_name": None,
}

UPSTREAM_MOD_MAP = {
    "contains":     ("ok", "contains"),
    "startswith":   ("ok", "startswith"),
    "endswith":     ("ok", "endswith"),
    "re":           ("ok", "re"),
    "all":          ("ok", "all"),
    "any":          ("ok", "any"),
    "exact":        ("ok", "exact"),
    "gt":           ("ok", "gt"),
    "gte":          ("ok", "gte"),
    "lt":           ("ok", "lt"),
    "lte":          ("ok", "lte"),
    "cidr":         ("reject", "unsupported_modifier: cidr"),
    "base64":       ("reject", "unsupported_modifier: base64"),
    "base64offset": ("reject", "unsupported_modifier: base64"),
    "utf16":        ("reject", "unsupported_modifier: encoding"),
    "wide":         ("reject", "unsupported_modifier: encoding"),
    "ascii":        ("reject", "unsupported_modifier: encoding"),
}


class ConvertError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _lowercase_value(v):
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, list):
        return [_lowercase_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _lowercase_value(val) for k, val in v.items()}
    return v


def _map_modifiers(mods: list[str]) -> list[str]:
    out: list[str] = []
    for m in mods:
        m_low = m.lower()
        if m_low not in UPSTREAM_MOD_MAP:
            raise ConvertError("unknown_modifier", m)
        status, target = UPSTREAM_MOD_MAP[m_low]
        if status == "reject":
            code = target.split(":", 1)[0].strip()
            raise ConvertError(code, target)
        out.append(target)
    return out


def _map_sigma_field(name: str) -> Optional[str]:
    low = name.lower()
    if low in SIGMA_FIELD_MAP:
        return SIGMA_FIELD_MAP[low]
    return low


def _convert_single_map(block: dict, event_type: str) -> dict:
    """Convert a single dict of {field|mods: value}. Returns {} when every field is dropped."""
    out: dict[str, Any] = {}
    allowed_fields = SIGMA_FIELDS_BY_EVENT_TYPE[event_type]
    for raw_key, raw_val in block.items():
        field, mods = _strip_modifiers(raw_key)
        mapped = _map_sigma_field(field)
        if mapped is None:
            continue
        mapped_mods = _map_modifiers(mods)
        if mapped not in allowed_fields:
            raise ConvertError("unmapped_field", f"{field} -> {mapped}")
        new_key = mapped if not mapped_mods else f"{mapped}|" + "|".join(mapped_mods)
        if "re" in mapped_mods or mapped in SIGMA_ENUM_FIELDS:
            out[new_key] = raw_val
        else:
            out[new_key] = _lowercase_value(raw_val)
    return out


def _convert_sigma_block(block, event_type: str):
    """Convert a selection/filter block.

    Returns ``dict`` for the single-map shape (Sigma's default) or
    ``list[dict]`` for the OR'd list-of-maps shape (common in SigmaHQ).
    Raises ConvertError if the entire block ends up empty after mapping.
    """
    if isinstance(block, list):
        converted: list[dict] = []
        for i, item in enumerate(block):
            if not isinstance(item, dict):
                raise ConvertError("bad_selection",
                                   f"selection list entry [{i}] must be a mapping")
            sub = _convert_single_map(item, event_type)
            if sub:
                converted.append(sub)
        if not converted:
            raise ConvertError("empty_selection",
                               "selection list empty after dropping unmapped fields")
        return converted[0] if len(converted) == 1 else converted
    if not isinstance(block, dict):
        raise ConvertError("bad_selection", "selection/filter must be a mapping or list")
    out = _convert_single_map(block, event_type)
    if not out:
        raise ConvertError("empty_selection", "selection empty after mapping")
    return out


def _extract_mitre(tags: list[str], catalog: dict) -> dict:
    if not tags:
        raise ConvertError("mitre_missing", "no tags on rule")
    tech_re = re.compile(r"^attack\.t(\d+)(?:\.(\d+))?$", re.IGNORECASE)
    tac_re = re.compile(r"^attack\.([a-z\-]+)$", re.IGNORECASE)
    techniques: list[str] = []
    tactic_names: list[str] = []
    for t in tags:
        ts = str(t).strip()
        m = tech_re.match(ts)
        if m:
            main, sub = m.group(1), m.group(2)
            tid = f"T{main}" + (f".{sub}" if sub else "")
            if tid not in techniques:
                techniques.append(tid)
            continue
        m2 = tac_re.match(ts)
        if m2:
            name = m2.group(1).lower()
            if name in TACTIC_NAME_TO_ID and name not in tactic_names:
                tactic_names.append(name)
    if not techniques:
        raise ConvertError("mitre_missing", "no attack.tNNNN tags")

    def _entry(tid: str, preferred_tactic: Optional[str] = None) -> dict:
        if tid not in catalog:
            raise ConvertError("mitre_technique_unknown", tid)
        name, primary_tac = catalog[tid]
        tactic_id = primary_tac
        tactic_name = MITRE_TACTICS[primary_tac]
        if preferred_tactic and preferred_tactic in TACTIC_NAME_TO_ID:
            tactic_id = TACTIC_NAME_TO_ID[preferred_tactic]
            tactic_name = preferred_tactic
        return {
            "tactic_id": tactic_id,
            "tactic": tactic_name,
            "technique_id": tid,
            "technique": name,
        }

    preferred = tactic_names[0] if tactic_names else None
    primary = _entry(techniques[0], preferred)
    secondary = [_entry(t) for t in techniques[1:]]
    out: dict[str, Any] = {"primary": primary}
    if secondary:
        out["secondary"] = secondary
    return out


def _sigma_severity(level) -> str:
    if level is None or level == "":
        return "medium"
    s = str(level).lower()
    if s in SEVERITY_ENUM:
        return s
    if s == "informational":
        return "low"
    return "medium"


def convert_sigma(upstream: dict, source_name: str, source_url: str,
                  state: dict, catalog: dict) -> dict:
    logsource = upstream.get("logsource") or {}
    product = (logsource.get("product") or "").lower()
    category = (logsource.get("category") or "").lower()
    key = (product, category)
    if key not in LOGSOURCE_TO_EVENT_TYPE:
        raise ConvertError("non_endpoint_logsource", f"logsource={product}/{category}")
    et_entry = LOGSOURCE_TO_EVENT_TYPE[key]
    extra_fields: dict[str, Any] = {}
    if isinstance(et_entry, tuple):
        event_type, extra_fields = et_entry
    else:
        event_type = et_entry

    detection = upstream.get("detection") or {}
    if not isinstance(detection, dict):
        raise ConvertError("bad_detection", "missing detection block")

    selection_block = None
    selection_groups: dict[str, Any] = {}
    filter_block = None
    filter_groups: dict[str, Any] = {}
    condition = detection.get("condition")
    for k, v in detection.items():
        if k == "condition":
            continue
        if k == "selection":
            selection_block = v
        elif k == "filter":
            filter_block = v
        elif isinstance(k, str) and k.startswith("selection_"):
            selection_groups[k] = v
        elif isinstance(k, str) and k.startswith("filter_"):
            # Real-world Sigma uses filter_legitimate, filter_microsoft, etc.
            # Each is an independent suppression group.
            filter_groups[k] = v

    converted_selection: dict[str, Any]
    if selection_block is not None and not selection_groups:
        converted_selection = _convert_sigma_block(selection_block, event_type)
    elif selection_groups:
        converted_selection = {}
        for gname, gval in selection_groups.items():
            converted_selection[gname] = _convert_sigma_block(gval, event_type)
        if condition is None:
            condition = " or ".join(selection_groups.keys())
    else:
        raise ConvertError("empty_selection", "no selection block present")

    converted_filter = None
    if filter_block is not None and not filter_groups:
        converted_filter = _convert_sigma_block(filter_block, event_type)
    elif filter_groups:
        # Collapse named filter groups into Shape B (list of maps, OR'd).
        # If `filter:` is also present, prepend it as the first group.
        groups_list: list[dict] = []
        if filter_block is not None:
            base = _convert_sigma_block(filter_block, event_type)
            groups_list.append(base if isinstance(base, dict) else base[0])
        for _, gv in filter_groups.items():
            conv = _convert_sigma_block(gv, event_type)
            if isinstance(conv, dict):
                groups_list.append(conv)
            elif isinstance(conv, list):
                groups_list.extend(conv)
        converted_filter = groups_list if len(groups_list) > 1 else groups_list[0]

    if extra_fields and not selection_groups:
        for k, v in extra_fields.items():
            converted_selection[k] = v

    tags = _ensure_list(upstream.get("tags"))
    sigma_mitre_auto_injected = False
    try:
        mitre_block = _extract_mitre(tags, catalog)
    except ConvertError as ce:
        if ce.code in ("mitre_missing", "mitre_technique_unknown"):
            # Mirror the permissive YARA path: rather than reject, default
            # to a broad MITRE classification. Operator sees the WARN in
            # the [OK] summary and via the extra "imported:auto-mitre" tag.
            fallback_tag = f"attack.t{YARA_DEFAULT_MITRE_TECHNIQUE[1:].lower()}"
            mitre_block = _extract_mitre([fallback_tag], catalog)
            sigma_mitre_auto_injected = True
        else:
            raise

    # Normalize Windows paths to forward slashes for human-readable embedding
    # in YAML strings — mirrors the YARA fix and avoids ugly \-escapes when
    # the rule is consumed by downstream tools.
    safe_url = str(source_url).replace("\\", "/")
    refs = _ensure_list(upstream.get("references"))
    refs = [str(r).replace("\\", "/") for r in refs]
    if safe_url and safe_url not in refs:
        refs.insert(0, safe_url)

    sigma_id = next_id(state, "sigma")
    title = str(upstream.get("title") or sigma_id).strip().splitlines()[0][:100]
    desc_upstream = str(upstream.get("description") or "").strip()
    if not desc_upstream:
        desc_upstream = "Imported detection rule."
    description = (
        f"{desc_upstream}\n\n"
        f"Imported from {source_name} at {safe_url}. "
        f"Status: experimental - review before promotion. "
        f"Known limitation: this rule was machine-converted and may need tuning for your environment."
    )

    out: dict[str, Any] = {
        "id": sigma_id,
        "title": title,
        "status": "experimental",
        "description": description,
        "references": refs,
        "author": f"ruleforge-converter (source: {source_name})",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": _sigma_severity(upstream.get("level")),
        "mitre": mitre_block,
        "event_type": event_type,
        "selection": converted_selection,
    }
    if converted_filter:
        out["filter"] = converted_filter
    if condition is not None and (selection_groups or filter_block is not None):
        out["condition"] = str(condition)
    tags_out = ["imported", f"source:{source_name}"]
    if sigma_mitre_auto_injected:
        tags_out.append("imported:auto-mitre")
    out["tags"] = tags_out
    out["version"] = 1
    out["revision"] = 1
    out["dedup_window_seconds"] = DEFAULT_DEDUP_WINDOW
    # Inject default auto_action based on event_type unless upstream already
    # set one (Sigma upstream effectively never does, since auto_action is
    # an EaglEye-specific field). Tag the rule so the operator can grep for
    # auto-injected actions before promoting to stable.
    if "auto_action" not in upstream:
        out["auto_action"] = SIGMA_AUTO_ACTION_BY_EVENT_TYPE.get(event_type, "suspend_process")
        tags_out.append("imported:auto-action")
    else:
        out["auto_action"] = upstream["auto_action"]
    return out


# ---------------------------------------------------------------------------
#  YAML dump (ordered keys)
# ---------------------------------------------------------------------------

SIGMA_KEY_ORDER = ["id", "title", "status", "description", "references", "author",
                   "date", "severity", "mitre", "event_type", "selection", "filter",
                   "condition", "tags", "version", "revision",
                   "dedup_window_seconds", "auto_action"]


def _ordered_sigma_for_dump(rule: dict) -> dict:
    out = {}
    for k in SIGMA_KEY_ORDER:
        if k in rule:
            out[k] = rule[k]
    for k, v in rule.items():
        if k not in out:
            out[k] = v
    return out


class _OrderedDumper(yaml.SafeDumper):
    pass


def _ordered_dict_representer(dumper, data):
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items(), flow_style=False)


def _string_representer(dumper, data):
    """Use literal-block style (|) for multi-line strings; plain otherwise."""
    if isinstance(data, str) and "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_OrderedDumper.add_representer(dict, _ordered_dict_representer)
_OrderedDumper.add_representer(str, _string_representer)


def dump_sigma_yaml(rule: dict) -> str:
    ordered = _ordered_sigma_for_dump(rule)
    return yaml.dump(ordered, Dumper=_OrderedDumper, sort_keys=False,
                     default_flow_style=False, allow_unicode=True, width=1000)


# ---------------------------------------------------------------------------
#  YARA converter
# ---------------------------------------------------------------------------

def _sanitize_pascal(name: str) -> str:
    parts = re.split(r"[^A-Za-z0-9]+", name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _infer_yara_family(rule_name: str) -> Optional[str]:
    base = re.sub(r"(_|^)(detection|generic|rule|sig|signature|hunting)(?=_|$)",
                  "", rule_name, flags=re.IGNORECASE)
    base = re.sub(r"[_\-]+", "_", base).strip("_")
    if not base:
        return None
    return _sanitize_pascal(base.split("_")[0])


def _yara_severity_heuristic(family: str) -> str:
    f = family.lower()
    if any(k in f for k in ("mimikatz", "lockbit", "ransom", "cobaltstrike", "emotet")):
        return "critical"
    return "high"


YARA_KEYWORDS_NO_GLUE = {
    "and", "or", "not", "of", "any", "all", "for", "in", "them",
    "true", "false", "matches", "contains", "startswith", "endswith",
    "icontains", "istartswith", "iendswith", "iequals", "at",
}


def _join_yara_terms(terms: list[str]) -> str:
    out = []
    for i, t in enumerate(terms):
        if i == 0:
            out.append(t)
            continue
        prev = terms[i - 1]
        if t in (",", ")", "]"):
            out.append(t)
        elif prev in ("(", "["):
            out.append(t)
        elif t in ("(", "["):
            if prev in YARA_KEYWORDS_NO_GLUE:
                out.append(" " + t)
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", prev) or prev == ")":
                out.append(t)
            else:
                out.append(" " + t)
        else:
            out.append(" " + t)
    return "".join(out)


def _condition_text(parsed: dict, raw_text: str) -> str:
    terms = parsed.get("condition_terms") or []
    if terms:
        return _join_yara_terms(terms)
    m = re.search(r"condition\s*:\s*(.+?)\}\s*$", raw_text, re.DOTALL)
    return m.group(1).strip() if m else ""


def _format_yara_string(s: dict) -> str:
    name = s.get("name")
    typ = s.get("type", "text")
    val = s.get("value", "")
    mods = s.get("modifiers") or []
    if typ == "text":
        text = val
        if not (text.startswith('"') and text.endswith('"')):
            text = '"' + text.replace('"', '\\"') + '"'
        body = text
    elif typ == "byte":
        body = val if val.strip().startswith("{") else "{ " + val + " }"
    elif typ == "regex":
        body = val if val.startswith("/") else "/" + val + "/"
    else:
        body = val
    mod_str = (" " + " ".join(mods)) if mods else ""
    return f"        {name} = {body}{mod_str}"


YARA_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*$', re.MULTILINE)
YARA_ALLOWED_IMPORTS = {"pe", "math", "hash", "dotnet", "macho", "console", "time"}


def _convert_yara_one_rule(parsed: dict, raw_text: str, imports: list[str],
                            source_name: str, source_url: str,
                            state: dict, catalog: dict) -> tuple[str, dict]:
    """Convert a single parsed plyara dict. File-level checks (parse error,
    disallowed modules) are the caller's responsibility."""
    raw_meta = _yara_meta_dict(parsed)
    cond_text = _condition_text(parsed, raw_text)
    if not cond_text:
        raise ConvertError("yara_no_structural_anchor", "no condition parsed")

    # Filesize injection below makes every converted rule satisfy the structural-
    # anchor requirement, so we no longer hard-reject rules that lack PE/ELF
    # magic. The validator surfaces a WARN ("yara_no_pe_anchor") on the rebuilt
    # rule so the operator knows the rule scans every file under the cap.

    cond_stripped = cond_text.strip()
    if SINGLE_STRING_RE.fullmatch(cond_stripped) or cond_stripped == "1 of them":
        raise ConvertError("yara_single_string", "single-string condition")

    has_n_of_paren = bool(re.search(r"\d+\s+of\s+\(", cond_text))
    has_of_them = bool(re.search(r"\bof\s+them\b", cond_text))
    has_of_paren = bool(re.search(r"\bof\s+\(\s*\$", cond_text))
    has_and_strings = bool(re.search(r"\$[A-Za-z0-9_]+\s+and\s+\$", cond_text))
    has_or_strings = bool(re.search(r"\$[A-Za-z0-9_]+\s+or\s+\$", cond_text))
    if not (has_n_of_paren or has_of_them or has_of_paren or has_and_strings or has_or_strings):
        refs = set(re.findall(r"\$[A-Za-z0-9_]+", cond_text))
        if len(refs) <= 1:
            raise ConvertError("yara_single_string", "single-string condition")

    family = raw_meta.get("family") or raw_meta.get("malware_family")
    if not family:
        family = _infer_yara_family(parsed.get("rule_name", ""))
    if not family:
        raise ConvertError("yara_family_missing", "could not determine family")
    family = _sanitize_pascal(str(family))

    mitre_str = ""
    for k in ("mitre", "mitre_attack", "tags"):
        if k in raw_meta and raw_meta[k]:
            mitre_str = str(raw_meta[k])
            break
    tech_ids: list[str] = []
    for t in re.findall(r"attack\.t(\d+(?:\.\d+)?)", mitre_str, re.IGNORECASE):
        tid = "T" + t
        if tid not in tech_ids:
            tech_ids.append(tid)
    if not tech_ids:
        for t in re.findall(r"\bT(\d+(?:\.\d+)?)\b", mitre_str):
            tid = "T" + t
            if tid not in tech_ids:
                tech_ids.append(tid)
    mitre_auto_injected = False
    if not tech_ids:
        # Permissive fallback for community YARA corpora (Yara-Rules, etc.)
        # that omit MITRE meta entirely. Pick a defensible default; surface
        # a WARN so the operator knows the categorization is generic.
        tech_ids = [YARA_DEFAULT_MITRE_TECHNIQUE]
        mitre_auto_injected = True

    yara_id = next_id(state, "yara")
    rule_ident = f"Y_{yara_id.split('-')[1]}_{family}"

    # YARA meta strings use C-like escapes; normalize backslashes (Windows paths)
    # and quotes/newlines so the emitted rule re-parses cleanly.
    safe_url = str(source_url).replace("\\", "/")
    description = (str(raw_meta.get("description") or "Imported YARA rule.").strip()
                   + f" Imported from {source_name} at {safe_url}. "
                   + "Status: experimental - review before promotion.")
    description = description.replace("\\", "/").replace('"', "'").replace("\n", " ")
    severity = str(raw_meta.get("severity") or _yara_severity_heuristic(family)).lower()
    if severity not in SEVERITY_ENUM:
        severity = "high"
    reference = (safe_url or str(raw_meta.get("reference") or "")).replace("\\", "/").replace('"', "'")

    filesize_injected = False
    if "filesize" not in cond_text:
        cond_text = f"({cond_text.strip()}) and filesize < 50MB"
        filesize_injected = True

    yara_strings = parsed.get("strings") or []
    strings_block = ""
    if yara_strings:
        formatted = "\n".join(_format_yara_string(s) for s in yara_strings)
        strings_block = "    strings:\n" + formatted + "\n\n"

    mitre_meta_val = ",".join(tech_ids)
    # Preserve any allowed imports the upstream rule depends on (`pe`, `math`,
    # `hash`, etc.). Without these the rebuilt rule fails to re-parse under
    # plyara/yara when the condition references module functions.
    safe_imports = [imp for imp in imports if imp in YARA_ALLOWED_IMPORTS]
    import_header = "".join(f'import "{imp}"\n' for imp in safe_imports)
    if import_header:
        import_header += "\n"
    header_block = (
        f"/*\n"
        f" * {yara_id}  {family}\n"
        f" *\n"
        f" * {description}\n"
        f" *\n"
        f" * Source: {safe_url}\n"
        f" */\n"
    )
    # YARA matches file content → default action is quarantine the file.
    # Honor an upstream-set auto_action if present (rare in community corpora).
    yara_auto_action = str(raw_meta.get("auto_action") or YARA_DEFAULT_AUTO_ACTION)
    meta_lines = [
        f'        id          = "{yara_id}"',
        f'        family      = "{family}"',
        f'        description = "{description}"',
        f'        author      = "ruleforge-converter (source: {source_name})"',
        f'        date        = "{datetime.now(timezone.utc).strftime("%Y-%m-%d")}"',
        f'        severity    = "{severity}"',
        f'        auto_action = "{yara_auto_action}"',
        f'        mitre       = "{mitre_meta_val}"',
    ]
    # Production-form MITRE keys per RULE_AUTHORING.md §6 — drop-in
    # compatible with the EDR's strict YARA schema.
    primary_tid = tech_ids[0]
    if primary_tid in catalog:
        p_name, p_tac_id = catalog[primary_tid]
        p_tac_name = MITRE_TACTICS.get(p_tac_id, "")
        meta_lines.append(f'        mitre_primary_tactic        = "{p_tac_name}"')
        meta_lines.append(f'        mitre_primary_tactic_id     = "{p_tac_id}"')
        meta_lines.append(f'        mitre_primary_technique_id  = "{primary_tid}"')
        meta_lines.append(f'        mitre_primary_technique     = "{p_name}"')
    secondary_parts: list[str] = []
    for tid in tech_ids[1:]:
        if tid in catalog:
            s_name, s_tac_id = catalog[tid]
            secondary_parts.append(f"{s_tac_id}/{tid}/{s_name}")
    if secondary_parts:
        # Semicolon-delimited per rule_schemas.html §mitre §yara:
        # "tactic_id/technique_id/technique_name;tactic_id/..."
        meta_lines.append(
            f'        mitre_secondary             = "{";".join(secondary_parts)}"'
        )
    if reference:
        meta_lines.append(f'        reference   = "{reference}"')

    cond_comment = "    // auto-injected: filesize cap\n" if filesize_injected else ""

    body = (
        import_header
        + header_block
        + f"rule {rule_ident}\n"
        + "{\n"
        + "    meta:\n"
        + "\n".join(meta_lines) + "\n\n"
        + strings_block
        + cond_comment
        + "    condition:\n"
        + f"        {cond_text}\n"
        + "}\n"
    )

    meta_out = {
        "id": yara_id,
        "family": family,
        "description": description,
        "author": f"ruleforge-converter (source: {source_name})",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "severity": severity,
        "mitre": mitre_meta_val,
        "filesize_injected": filesize_injected,
        "mitre_auto_injected": mitre_auto_injected,
    }
    return body, meta_out


def convert_yara_all(raw_text: str, source_name: str, source_url: str,
                     state: dict, catalog: dict) -> list[tuple[str, Any]]:
    """Parse a YARA file, do file-level checks, convert each rule.

    Returns a list with one entry per upstream rule:
      ``("ok", (body_text, meta_dict))`` on success
      ``("error", (ConvertError, rule_name))`` on per-rule failure

    File-level errors (parse failure, disallowed module) still raise
    immediately, since no rule from the file can be safely converted.
    """
    if plyara is None:
        raise ConvertError("no_plyara", "plyara not installed")
    try:
        parsed_list = plyara.Plyara().parse_string(raw_text)
    except Exception as exc:
        raise ConvertError("yara_parse_error", str(exc))
    if not parsed_list:
        raise ConvertError("yara_parse_error", "no rules in input")
    for mod in YARA_DISALLOWED_MODULES:
        if re.search(rf'\bimport\s+"{mod}"', raw_text) or re.search(rf"\b{mod}\.", raw_text):
            raise ConvertError(f"yara_disallowed_module: {mod}", mod)
    imports = YARA_IMPORT_RE.findall(raw_text)

    results: list[tuple[str, Any]] = []
    for parsed in parsed_list:
        rule_name = parsed.get("rule_name", "unknown")
        try:
            body, meta = _convert_yara_one_rule(
                parsed, raw_text, imports, source_name, source_url, state, catalog
            )
            results.append(("ok", (body, meta)))
        except ConvertError as ce:
            results.append(("error", (ce, rule_name)))
    return results


def convert_yara(raw_text: str, source_name: str, source_url: str,
                 state: dict, catalog: dict) -> tuple[str, dict]:
    """Backward-compatible wrapper that returns the FIRST rule's result.

    File-level errors propagate. Per-rule errors from the first rule are
    re-raised so existing call sites and tests see the same semantics.
    """
    results = convert_yara_all(raw_text, source_name, source_url, state, catalog)
    first_status, first_payload = results[0]
    if first_status == "error":
        raise first_payload[0]
    return first_payload


# ---------------------------------------------------------------------------
#  IOC handlers
# ---------------------------------------------------------------------------

def _ioc_iso_date(raw: str) -> str:
    if not raw:
        return ""
    return str(raw).split(" ")[0]


def process_bazaar_entries(entries: list[dict], state: dict, dry_run: bool = False) -> tuple[int, int, int]:
    seen = set(state["seen_hashes"].setdefault("malware_bazaar", []))
    out_path = IOC_DIR / "malware_bazaar.jsonl"
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    converted = rejected = skipped = 0
    fh = open(out_path, "a", encoding="utf-8") if not dry_run else io.StringIO()
    try:
        for entry in entries:
            sha = (entry.get("sha256_hash") or "").lower()
            if not SHA256_RE.fullmatch(sha):
                rejected += 1
                continue
            if sha in seen:
                skipped += 1
                continue
            doc = {
                "sha256": sha,
                "md5": (entry.get("md5_hash") or "").lower() or None,
                "imphash": (entry.get("imphash") or "").lower() or None,
                "verdict": "malicious",
                "family": entry.get("signature") or None,
                "type": entry.get("file_type") or None,
                "source": "malware_bazaar",
                "first_seen": _ioc_iso_date(entry.get("first_seen", "")),
                "last_seen": _ioc_iso_date(entry.get("last_seen", "")),
                "tags": entry.get("tags") or [],
            }
            fh.write(json.dumps(doc) + "\n")
            seen.add(sha)
            converted += 1
    finally:
        fh.close()
    state["seen_hashes"]["malware_bazaar"] = sorted(seen)
    if not dry_run:
        save_state(state)
    return converted, rejected, skipped


def process_cisa_kev_entries(entries: list[dict], state: dict, dry_run: bool = False) -> tuple[int, int, int]:
    seen = set(state["seen_hashes"].setdefault("cisa_kev", []))
    out_path = IOC_DIR / "cisa_kev.jsonl"
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    converted = rejected = skipped = 0
    fh = open(out_path, "a", encoding="utf-8") if not dry_run else io.StringIO()
    try:
        for entry in entries:
            cve = entry.get("cveID") or entry.get("cve") or ""
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                rejected += 1
                continue
            if cve in seen:
                skipped += 1
                continue
            doc = {
                "cve": cve,
                "vendor": entry.get("vendorProject") or entry.get("vendor") or "",
                "product": entry.get("product") or "",
                "short_description": entry.get("shortDescription") or entry.get("short_description") or "",
                "date_added": entry.get("dateAdded") or entry.get("date_added") or "",
                "required_action": entry.get("requiredAction") or entry.get("required_action") or "",
                "due_date": entry.get("dueDate") or entry.get("due_date") or "",
                "known_ransomware_use": str(entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "source": "cisa_kev",
            }
            fh.write(json.dumps(doc) + "\n")
            seen.add(cve)
            converted += 1
    finally:
        fh.close()
    state["seen_hashes"]["cisa_kev"] = sorted(seen)
    if not dry_run:
        save_state(state)
    return converted, rejected, skipped


def process_threatfox_entries(entries, state, limit=None):
    seen = set(state["seen_hashes"].setdefault("threatfox", []))
    IOC_DIR.mkdir(parents=True, exist_ok=True)
    out_path = IOC_DIR / "threatfox.jsonl"
    converted = rejected = skipped = 0
    n = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for entry in entries:
            if limit and n >= limit:
                break
            t = entry.get("ioc_type") or ""
            if t not in ("sha256_hash", "md5_hash", "sha1_hash"):
                continue
            sha = (entry.get("ioc") or "").lower()
            if t == "sha256_hash" and not SHA256_RE.fullmatch(sha):
                rejected += 1; continue
            key = f"{t}:{sha}"
            if key in seen:
                skipped += 1; continue
            doc = {
                "sha256": sha if t == "sha256_hash" else None,
                "md5": sha if t == "md5_hash" else None,
                "verdict": "malicious",
                "family": entry.get("malware") or None,
                "source": "threatfox",
                "first_seen": (entry.get("first_seen") or "").split(" ")[0],
                "last_seen": (entry.get("last_seen") or "").split(" ")[0],
                "tags": entry.get("tags") or [],
            }
            fh.write(json.dumps(doc) + "\n")
            seen.add(key)
            converted += 1; n += 1
    state["seen_hashes"]["threatfox"] = sorted(seen)
    save_state(state)
    return converted, rejected, skipped


def process_urlhaus_entries(entries, state, limit=None):
    seen = set(state["seen_hashes"].setdefault("urlhaus", []))
    IOC_DIR.mkdir(parents=True, exist_ok=True)
    out_path = IOC_DIR / "urlhaus.jsonl"
    converted = rejected = skipped = 0
    n = 0
    with open(out_path, "a", encoding="utf-8") as fh:
        for entry in entries:
            if limit and n >= limit:
                break
            sha = (entry.get("sha256_hash") or "").lower()
            if not SHA256_RE.fullmatch(sha):
                rejected += 1; continue
            if sha in seen:
                skipped += 1; continue
            doc = {
                "sha256": sha,
                "md5": (entry.get("md5_hash") or "").lower() or None,
                "imphash": (entry.get("imphash") or "").lower() or None,
                "verdict": "malicious",
                "family": entry.get("signature") or None,
                "type": entry.get("file_type") or None,
                "source": "urlhaus",
                "first_seen": (entry.get("firstseen") or "").split(" ")[0],
                "last_seen": (entry.get("lastseen") or "").split(" ")[0],
                "tags": entry.get("tags") or [],
            }
            fh.write(json.dumps(doc) + "\n")
            seen.add(sha)
            converted += 1; n += 1
    state["seen_hashes"]["urlhaus"] = sorted(seen)
    save_state(state)
    return converted, rejected, skipped


# ---------------------------------------------------------------------------
#  Rejection writer
# ---------------------------------------------------------------------------

def _write_rejection(path: Path, *, source: str, kind: str, reason: str,
                     detail: str, content: str, dry_run: bool = False) -> None:
    body = (
        f"SOURCE: {source}\n"
        f"TYPE: {kind}\n"
        f"REASON: {reason}\n"
        f"DETAIL: {detail}\n"
        f"TIMESTAMP: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n"
        f"---\n"
        f"{content}\n"
    )
    if dry_run:
        print(body)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
#  URL parsing / fetch
# ---------------------------------------------------------------------------

GH_BLOB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$")
# File extensions worth fetching during a tree walk. README, LICENSE, .gitignore,
# images, etc. get skipped at enumeration time so they don't burn API calls or
# show up as noise in the rejection log.
RULE_FILE_EXTS = (".yml", ".yaml", ".yar", ".yara", ".json")
# Tree URL: subpath optional. /tree/main walks the repo root; /tree/main/sub walks the subdir.
GH_TREE_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/tree/([^/]+?)(?:/(.+))?/?$")
GH_RAW_RE = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
# Bare repo: github.com/owner/repo (no /tree/, /blob/, or path component)
GH_BARE_REPO_RE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")


def rewrite_blob_to_raw(url: str) -> str:
    m = GH_BLOB_RE.match(url)
    if m:
        owner, repo, ref, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    return url


def list_github_tree(url: str, filter_substring: Optional[str] = None,
                     max_count: Optional[int] = None) -> list[str]:
    """Walk a GitHub tree URL, returning raw URLs of files within.

    When ``filter_substring`` is set, only files AND directories whose path
    contains the substring are visited. This is a critical optimization
    for the anonymous GitHub API rate limit (60 req/hour) — without it,
    a single ingest call against a large repo can exhaust the budget
    before producing any useful output.

    When ``max_count`` is set, recursion stops as soon as that many files
    have been collected.
    """
    m = GH_TREE_RE.match(url)
    if not m:
        return []
    owner, repo, ref, path = m.groups()
    path = path or ""
    if path:
        api = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    else:
        # Walk the repo root.
        api = f"https://api.github.com/repos/{owner}/{repo}/contents?ref={ref}"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = _req_get(api, headers=headers, timeout=30)
    if r.status_code == 403:
        raise RuntimeError(
            "GitHub anonymous rate limit hit (60 req/hour). "
            "Wait an hour, or set GITHUB_TOKEN env var to a personal-access "
            "token (read:public scope is enough)."
        )
    r.raise_for_status()
    items = r.json()
    if not isinstance(items, list):
        items = [items]
    flt = filter_substring.lower() if filter_substring else None
    out: list[str] = []
    for item in items:
        item_path = (item.get("path") or "").lower()
        if item.get("type") == "file":
            # Skip non-rule files (README, LICENSE, images, ...) at enumeration
            # time so they don't end up as bad_yaml rejections.
            if not item_path.endswith(RULE_FILE_EXTS):
                continue
            if flt and flt not in item_path:
                continue
            dl = item.get("download_url")
            if dl:
                out.append(dl)
            if max_count and len(out) >= max_count:
                return out
        elif item.get("type") == "dir":
            # When filtering, only recurse into dirs whose path contains the
            # substring — saves dozens of API calls on large repos.
            if flt and flt not in item_path:
                continue
            sub_url = f"https://github.com/{owner}/{repo}/tree/{ref}/{item['path']}"
            remaining = (max_count - len(out)) if max_count else None
            out.extend(list_github_tree(sub_url, filter_substring, remaining))
            if max_count and len(out) >= max_count:
                return out[:max_count]
    return out


def http_get(url: str) -> bytes:
    headers = {"User-Agent": "ruleforge/0.1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and "github" in url:
        headers["Authorization"] = f"Bearer {token}"
    r = _req_get(url, headers=headers)
    r.raise_for_status()
    return r.content


def detect_type(content: bytes, hint_url: str = "") -> str:
    lower = hint_url.lower()
    if lower.endswith((".yml", ".yaml")):
        return "sigma"
    if lower.endswith((".yar", ".yara")):
        return "yara"
    if lower.endswith(".json"):
        return "ioc"
    head = content[:1024].decode("utf-8", errors="ignore")
    head_stripped = head.lstrip().lower()
    # HTML pages (bare-repo URLs, 404 bodies, login walls) used to fall
    # through to "sigma" and explode in yaml.safe_load. Treat them as
    # unknown so the converter can reject cleanly.
    if head_stripped.startswith(("<!doctype", "<html", "<?xml")):
        return "unknown"
    if "logsource:" in head or "detection:" in head:
        return "sigma"
    if re.search(r"^rule\s+[A-Za-z_]", head, re.MULTILINE):
        return "yara"
    if head_stripped.startswith("{"):
        return "ioc"
    return "sigma"


# ---------------------------------------------------------------------------
#  Convert dispatch (one file)
# ---------------------------------------------------------------------------

def convert_one(content: bytes, kind: str, source_name: str, source_url: str,
                state: dict, catalog: dict, original_filename: str,
                dry_run: bool = False) -> str:
    # Empty / whitespace-only content can come from a fetch that hit a 200-OK
    # empty response or a server side outage. Reject early with a clean reason
    # rather than letting yaml.safe_load return None and crashing downstream.
    if not content or not content.strip():
        try:
            reject_name = Path(original_filename).name + ".reject.txt"
            _write_rejection(REJECT_DIR / reject_name,
                             source=source_url or original_filename,
                             kind=kind, reason="empty_content",
                             detail="zero-byte or whitespace-only content",
                             content="",
                             dry_run=dry_run)
        except Exception:
            pass
        return f"[REJECT] {original_filename}: empty_content"

    h = hashlib.sha256(content).hexdigest()
    hkey = f"sha256:{h}"
    seen_rules = set(state["seen_hashes"].setdefault("rules", []))
    if hkey in seen_rules:
        return f"[SKIP] {original_filename}: duplicate (sha256={h[:12]})"

    try:
        if kind == "sigma":
            try:
                upstream = yaml.safe_load(content)
            except yaml.YAMLError as ye:
                raise ConvertError("bad_yaml", f"YAML parse failed: {ye}")
            if not isinstance(upstream, dict):
                # Common cause: an HTML page (bare-repo URL or 404 with HTML body)
                # got handed to the sigma branch by detect_type's loose fallback.
                head = content[:80].decode("utf-8", errors="replace").strip()
                raise ConvertError(
                    "bad_yaml",
                    f"could not parse as Sigma dict (got {type(upstream).__name__}; "
                    f"head: {head!r})",
                )
            rule = convert_sigma(upstream, source_name, source_url, state, catalog)
            issues = validate_sigma(rule, catalog)
            errors = [i for i in issues if i.severity == ERROR]
            if errors:
                raise ConvertError(errors[0].code, errors[0].message)
            warns = [i for i in issues if i.severity == WARN]
            if "imported:auto-mitre" in (rule.get("tags") or []):
                warns.append(Issue(WARN, "mitre_auto_injected",
                                    f"upstream had no usable MITRE tags; defaulted to "
                                    f"{YARA_DEFAULT_MITRE_TECHNIQUE} — review categorization"))
            if dry_run:
                print(dump_sigma_yaml(rule))
                return f"[OK-DRY] {rule['id']} (dry-run)"
            SIGMA_DIR.mkdir(parents=True, exist_ok=True)
            out_path = SIGMA_DIR / f"{rule['id']}.yml"
            out_path.write_text(dump_sigma_yaml(rule), encoding="utf-8")
            seen_rules.add(hkey)
            state["seen_hashes"]["rules"] = sorted(seen_rules)
            save_state(state)
            wmsg = (" (" + "; ".join(str(w) for w in warns) + ")") if warns else ""
            return f"[OK] {rule['id']} -> {out_path}{wmsg}"

        elif kind == "yara":
            text = content.decode("utf-8", errors="replace")
            rule_results = convert_yara_all(text, source_name, source_url, state, catalog)

            # Single-rule file: preserve the historical summary shape.
            if len(rule_results) == 1:
                status, payload = rule_results[0]
                if status == "error":
                    raise payload[0]
                body, meta = payload
                issues = validate_yara(body, catalog)
                errors = [i for i in issues if i.severity == ERROR]
                if errors:
                    raise ConvertError(errors[0].code, errors[0].message)
                warns = [i for i in issues if i.severity == WARN]
                if meta.get("mitre_auto_injected"):
                    warns.append(Issue(WARN, "mitre_auto_injected",
                                        f"upstream had no MITRE tags; defaulted to "
                                        f"{YARA_DEFAULT_MITRE_TECHNIQUE} — review categorization"))
                if dry_run:
                    print(body)
                    return f"[OK-DRY] {meta['id']} (dry-run)"
                YARA_DIR.mkdir(parents=True, exist_ok=True)
                family_low = re.sub(r"[^a-z0-9]+", "_", meta["family"].lower()).strip("_")
                out_path = YARA_DIR / f"{meta['id']}_{family_low}.yar"
                out_path.write_text(body, encoding="utf-8")
                seen_rules.add(hkey)
                state["seen_hashes"]["rules"] = sorted(seen_rules)
                save_state(state)
                wmsg = (" (" + "; ".join(str(w) for w in warns) + ")") if warns else ""
                return f"[OK] {meta['id']} -> {out_path}{wmsg}"

            # Multi-rule file: convert each rule, write each successful one,
            # write a per-rule reject for failures. Print a per-rule summary
            # line so the operator sees what happened.
            n_ok = n_reject = 0
            ok_ids: list[str] = []
            for status, payload in rule_results:
                if status == "error":
                    err, rule_name = payload
                    base = Path(original_filename).stem
                    reject_path = REJECT_DIR / f"{base}_{rule_name}.reject.txt"
                    _write_rejection(reject_path,
                                     source=source_url or original_filename,
                                     kind="yara", reason=err.code,
                                     detail=err.detail or str(err),
                                     content=f"(rule {rule_name} from multi-rule file)",
                                     dry_run=dry_run)
                    n_reject += 1
                    print(f"  [REJECT] rule {rule_name}: {err.code}")
                    continue
                body, meta = payload
                issues = validate_yara(body, catalog)
                errors = [i for i in issues if i.severity == ERROR]
                if errors:
                    base = Path(original_filename).stem
                    reject_path = REJECT_DIR / f"{base}_{meta['id']}.reject.txt"
                    _write_rejection(reject_path,
                                     source=source_url or original_filename,
                                     kind="yara", reason=errors[0].code,
                                     detail=errors[0].message,
                                     content=body, dry_run=dry_run)
                    n_reject += 1
                    print(f"  [REJECT] {meta['id']}: {errors[0].code}")
                    continue
                warns = [i for i in issues if i.severity == WARN]
                if meta.get("mitre_auto_injected"):
                    warns.append(Issue(WARN, "mitre_auto_injected",
                                        f"defaulted to {YARA_DEFAULT_MITRE_TECHNIQUE}"))
                if dry_run:
                    print(body)
                else:
                    YARA_DIR.mkdir(parents=True, exist_ok=True)
                    family_low = re.sub(r"[^a-z0-9]+", "_", meta["family"].lower()).strip("_")
                    out_path = YARA_DIR / f"{meta['id']}_{family_low}.yar"
                    out_path.write_text(body, encoding="utf-8")
                n_ok += 1
                ok_ids.append(meta["id"])
                wmsg = (" (" + "; ".join(str(w) for w in warns) + ")") if warns else ""
                print(f"  [OK] {meta['id']} ({meta['family']}){wmsg}")

            if not dry_run and n_ok:
                seen_rules.add(hkey)
                state["seen_hashes"]["rules"] = sorted(seen_rules)
                save_state(state)
            if n_ok and not n_reject:
                return f"[OK] {original_filename}: {n_ok} rules converted ({', '.join(ok_ids)})"
            if n_ok:
                return (f"[OK-PARTIAL] {original_filename}: "
                        f"{n_ok} converted ({', '.join(ok_ids)}), {n_reject} rejected")
            return f"[REJECT] {original_filename}: 0 converted, {n_reject} rejected"

        elif kind == "ioc":
            try:
                doc = json.loads(content.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as je:
                raise ConvertError("bad_json", f"JSON parse failed: {je}")
            if not isinstance(doc, dict):
                raise ConvertError("bad_json", f"expected JSON object, got {type(doc).__name__}")
            if "vulnerabilities" in doc:
                c, r, s = process_cisa_kev_entries(doc.get("vulnerabilities", []), state, dry_run)
                return f"[OK] CISA KEV: {c} converted, {r} rejected, {s} skipped"
            if "data" in doc and isinstance(doc["data"], list):
                c, r, s = process_bazaar_entries(doc["data"], state, dry_run)
                return f"[OK] MalwareBazaar: {c} converted, {r} rejected, {s} skipped"
            raise ConvertError("unknown_ioc_shape", "expected 'vulnerabilities' or 'data'")

        elif kind == "unknown":
            raise ConvertError("unknown_content",
                               "could not detect content type (looks like HTML or "
                               "non-rule data); pass --type if you know the format")
        else:
            raise ConvertError("unknown_kind", kind)

    except ConvertError as ce:
        reject_name = Path(original_filename).name + ".reject.txt"
        reject_path = REJECT_DIR / reject_name
        _write_rejection(reject_path, source=source_url or original_filename,
                         kind=kind, reason=ce.code, detail=ce.detail or str(ce),
                         content=content.decode("utf-8", errors="replace"),
                         dry_run=dry_run)
        return f"[REJECT] {original_filename}: {ce.code} {ce.detail}"


# ---------------------------------------------------------------------------
#  CLI commands
# ---------------------------------------------------------------------------

def cmd_validate(args) -> int:
    catalog = load_mitre_catalog()
    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] file not found: {path}")
        return 2
    if path.suffix.lower() in (".yml", ".yaml"):
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        issues = validate_sigma(rule, catalog) if isinstance(rule, dict) else \
            [Issue(ERROR, "bad_yaml", "could not parse")]
    elif path.suffix.lower() in (".yar", ".yara"):
        issues = validate_yara(path, catalog)
    else:
        print(f"[ERROR] unknown extension: {path.suffix}")
        return 2
    errors = [i for i in issues if i.severity == ERROR]
    if not issues:
        print("No issues.")
    for i in issues:
        print(i)
    return 0 if not errors else 1


def cmd_convert(args) -> int:
    state = load_state()
    fetch_mitre_catalog_if_stale(state)
    catalog = load_mitre_catalog()
    path = Path(args.file)
    if not path.exists():
        print(f"[ERROR] file not found: {path}")
        return 2
    content = path.read_bytes()
    kind = (args.type if getattr(args, "type", None) else detect_type(content, path.name))
    summary = convert_one(content, kind, source_name="local", source_url=str(path),
                          state=state, catalog=catalog, original_filename=path.name,
                          dry_run=getattr(args, "dry_run", False))
    print(summary)
    converted = 1 if summary.startswith("[OK") else 0
    rejected = 1 if summary.startswith("[REJECT") else 0
    skipped = 1 if summary.startswith("[SKIP") else 0
    print(f"Done. Converted: {converted}, Rejected: {rejected}, Skipped (duplicate): {skipped}.")
    return 0 if converted else 1


def cmd_fetch(args) -> int:
    state = load_state()
    fetch_mitre_catalog_if_stale(state)
    catalog = load_mitre_catalog()
    url = args.url
    bare = GH_BARE_REPO_RE.match(url)
    if bare:
        owner, repo = bare.groups()
        print(f"[ERROR] Bare repository URL is not supported: {url}")
        print( "        Use one of:")
        print(f"          - a raw file URL:  https://raw.githubusercontent.com/{owner}/{repo}/<branch>/<path>")
        print(f"          - a tree URL:      https://github.com/{owner}/{repo}/tree/<branch>/<subdir>")
        print( "        Or for a preset corpus, use:  ruleforge.py ingest <source-name>")
        return 2
    targets: list[str] = []
    if GH_TREE_RE.match(url):
        try:
            targets = list_github_tree(
                url,
                filter_substring=getattr(args, "filter", None),
                max_count=getattr(args, "limit", None),
            )
        except RuntimeError as exc:
            print(f"[ERROR] {exc}")
            return 2
        # max_count is a hint; enforce it as a hard cap on the result list.
        if getattr(args, "limit", None):
            targets = targets[: args.limit]
    else:
        targets = [rewrite_blob_to_raw(url)]
    converted = rejected = skipped = 0
    for t in targets:
        try:
            content = http_get(t)
        except Exception as exc:
            print(f"[ERROR] fetch {t}: {exc}")
            rejected += 1
            continue
        kind = args.type if args.type else detect_type(content, t)
        summary = convert_one(content, kind, "fetch", t, state, catalog,
                              original_filename=Path(t).name, dry_run=args.dry_run)
        print(summary)
        if summary.startswith("[OK"):
            converted += 1
        elif summary.startswith("[SKIP"):
            skipped += 1
        else:
            rejected += 1
    print(f"Done. Converted: {converted}, Rejected: {rejected}, Skipped (duplicate): {skipped}.")
    return 0


INGEST_PRESETS = {
    "sigmahq":         ("github_tree", "https://github.com/SigmaHQ/sigma/tree/master/rules/windows", "sigmahq"),
    "neo23x0":         ("github_tree", "https://github.com/Neo23x0/signature-base/tree/master/yara", "neo23x0"),
    "yara-rules":      ("github_tree", "https://github.com/Yara-Rules/rules/tree/master/malware", "yara-rules"),
    "abuse-bazaar":    ("bazaar_api", None, "malware_bazaar"),
    "abuse-threatfox": ("threatfox_api", None, "threatfox"),
    "abuse-urlhaus":   ("urlhaus_api", None, "urlhaus"),
    "cisa-kev":        ("cisa_kev_url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cisa_kev"),
}


def cmd_ingest(args) -> int:
    state = load_state()
    fetch_mitre_catalog_if_stale(state)
    catalog = load_mitre_catalog()
    name = args.source
    if name not in INGEST_PRESETS:
        print(f"[ERROR] unknown source {name}. Valid: {sorted(INGEST_PRESETS)}")
        return 2
    kind, url, source_name = INGEST_PRESETS[name]
    converted = rejected = skipped = 0

    if kind == "github_tree":
        try:
            targets = list_github_tree(url, filter_substring=args.filter,
                                       max_count=args.limit)
        except RuntimeError as exc:
            print(f"[ERROR] {exc}")
            return 2
        if args.limit:
            targets = targets[: args.limit]
        for t in targets:
            try:
                content = http_get(t)
            except Exception as exc:
                print(f"[ERROR] fetch {t}: {exc}")
                rejected += 1
                continue
            detect_kind = detect_type(content, t)
            summary = convert_one(content, detect_kind, source_name, t,
                                  state, catalog, original_filename=Path(t).name)
            print(summary)
            if summary.startswith("[OK"):
                converted += 1
            elif summary.startswith("[SKIP"):
                skipped += 1
            else:
                rejected += 1

    elif kind == "bazaar_api":
        r = _req_post("https://mb-api.abuse.ch/api/v1/",
                       data={"query": "get_recent", "selector": "time"})
        r.raise_for_status()
        data = r.json().get("data", []) or []
        if args.limit:
            data = data[: args.limit]
        c, rj, sk = process_bazaar_entries(data, state)
        converted += c; rejected += rj; skipped += sk

    elif kind == "threatfox_api":
        r = _req_post("https://threatfox-api.abuse.ch/api/v1/",
                       json={"query": "get_iocs", "days": 1})
        r.raise_for_status()
        body = r.json()
        entries = body.get("data") or []
        c, rj, sk = process_threatfox_entries(entries, state, limit=args.limit)
        converted += c; rejected += rj; skipped += sk

    elif kind == "urlhaus_api":
        r = _req_get("https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/")
        r.raise_for_status()
        body = r.json()
        entries = body.get("payloads") or []
        c, rj, sk = process_urlhaus_entries(entries, state, limit=args.limit)
        converted += c; rejected += rj; skipped += sk

    elif kind == "cisa_kev_url":
        content = http_get(url)
        doc = json.loads(content.decode("utf-8"))
        vulns = doc.get("vulnerabilities", []) or []
        if args.limit:
            vulns = vulns[: args.limit]
        c, rj, sk = process_cisa_kev_entries(vulns, state)
        converted += c; rejected += rj; skipped += sk

    print(f"Done. Converted: {converted}, Rejected: {rejected}, Skipped (duplicate): {skipped}.")
    return 0


def cmd_list(args) -> int:
    types = [args.type] if args.type else ["sigma", "yara", "ioc", "rejected"]
    for t in types:
        d = OUTPUT / (t if t != "ioc" else "iocs")
        if not d.exists():
            print(f"({t}: nothing yet)")
            continue
        files = sorted(d.glob("*"))
        print(f"\n== {t} ({len(files)}) ==")
        for f in files:
            sz = f.stat().st_size
            print(f"  {f.name:50s}  {sz:>10d} B")
    return 0


def cmd_stats(args) -> int:
    state = load_state()
    sigma_count = len(list((OUTPUT / "sigma").glob("*.yml"))) if (OUTPUT / "sigma").exists() else 0
    yara_count = len(list((OUTPUT / "yara").glob("*.yar"))) if (OUTPUT / "yara").exists() else 0
    rejected_count = len(list((OUTPUT / "rejected").glob("*"))) if (OUTPUT / "rejected").exists() else 0
    ioc_files = list((OUTPUT / "iocs").glob("*.jsonl")) if (OUTPUT / "iocs").exists() else []
    ioc_count = 0
    by_source: dict[str, int] = {}
    for f in ioc_files:
        n = sum(1 for _ in f.open(encoding="utf-8"))
        ioc_count += n
        by_source[f.stem] = n
    sev_counts: dict[str, int] = {}
    sigma_dir = OUTPUT / "sigma"
    if sigma_dir.exists():
        for f in sigma_dir.glob("*.yml"):
            try:
                d = yaml.safe_load(f.read_text(encoding="utf-8"))
                sev_counts[d.get("severity", "?")] = sev_counts.get(d.get("severity", "?"), 0) + 1
            except Exception:
                pass
    print(f"Sigma rules:    {sigma_count}")
    print(f"YARA rules:     {yara_count}")
    print(f"IOCs:           {ioc_count}")
    for src, n in by_source.items():
        print(f"  {src:>20s}: {n}")
    print(f"Rejected:       {rejected_count}")
    if sev_counts:
        print("Severity (sigma):")
        for s, n in sorted(sev_counts.items()):
            print(f"  {s:>10s}: {n}")
    print(f"State:")
    print(f"  next_sigma_id: {state.get('next_sigma_id')}")
    print(f"  next_yara_id:  {state.get('next_yara_id')}")
    print(f"  next_ioc_id:   {state.get('next_ioc_id')}")
    return 0


# ---------------------------------------------------------------------------
#  Entry point
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
#  Interactive mode
# ---------------------------------------------------------------------------

INTERACTIVE_HELP = """
Just paste / type one of:

  https://...                  -> fetch (auto-detects raw/blob/tree)
  /path/to/rule.yml            -> convert local file
  /path/to/rule.yar
  /path/to/feed.json
  <preset-name>                -> ingest a built-in source. Available presets:
                                  sigmahq, neo23x0, yara-rules, abuse-bazaar,
                                  abuse-threatfox, abuse-urlhaus, cisa-kev

Built-in commands at the prompt:
  list                         show output/ contents
  stats                        show counts and severity distribution
  validate <file>              validate a file already in EaglEye format
  insecure on | insecure off   toggle TLS verification (default: on)
  help                         show this help
  quit / exit / q              leave interactive mode
"""


def _classify_input(text: str) -> str:
    """Return one of: 'url', 'preset', 'file', 'unknown'."""
    t = text.strip()
    if not t:
        return "unknown"
    if t.lower().startswith(("http://", "https://")):
        return "url"
    if t in INGEST_PRESETS:
        return "preset"
    if Path(t).expanduser().exists():
        return "file"
    return "unknown"


def _prompt_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        ans = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not ans:
        return default
    return ans in ("y", "yes")


def _prompt_int(prompt: str, default: Optional[int]) -> Optional[int]:
    default_str = "" if default is None else str(default)
    try:
        ans = input(f"{prompt} [{default_str}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not ans:
        return default
    try:
        return int(ans)
    except ValueError:
        print(f"  (not a number; using {default})")
        return default


def _prompt_str(prompt: str, default: str = "") -> str:
    try:
        ans = input(f"{prompt} [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return ans or default


def _interactive_run_fetch(url: str, session: dict) -> None:
    is_tree = bool(GH_TREE_RE.match(url))
    limit = filt = None
    if is_tree:
        print("  (tree URL — fetches every file matching filter/limit)")
        limit = _prompt_int("  Limit number of files", default=50)
        filt = _prompt_str("  Filter substring (blank = no filter)", default="") or None
    args = SimpleNamespace(
        url=url, type=None, dry_run=False,
        limit=limit, filter=filt, insecure=session["insecure"],
    )
    if session["insecure"]:
        os.environ["RULEFORGE_INSECURE"] = "1"
    cmd_fetch(args)


def _interactive_run_ingest(name: str, session: dict) -> None:
    limit = _prompt_int("  Limit number of items", default=50)
    filt = _prompt_str("  Filter substring (blank = no filter)", default="") or None
    args = SimpleNamespace(
        source=name, limit=limit, filter=filt, since=None,
        insecure=session["insecure"],
    )
    if session["insecure"]:
        os.environ["RULEFORGE_INSECURE"] = "1"
    cmd_ingest(args)


def _interactive_run_convert(path: str) -> None:
    args = SimpleNamespace(file=path, type=None, dry_run=False)
    cmd_convert(args)


def cmd_interactive(args=None) -> int:
    """Drop into an interactive REPL — auto-detects URLs / presets / files."""
    print("RuleForge interactive mode. Type 'help' for options, 'quit' to exit.")
    print(f"Presets: {', '.join(INGEST_PRESETS.keys())}")
    session = {"insecure": False}
    while True:
        try:
            raw = input("\nruleforge> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not raw:
            continue
        low = raw.lower()
        if low in ("quit", "exit", "q"):
            return 0
        if low in ("help", "?", "-h", "--help"):
            print(INTERACTIVE_HELP)
            continue
        if low == "list":
            cmd_list(SimpleNamespace(type=None))
            continue
        if low.startswith("list "):
            t = raw.split(None, 1)[1].strip()
            if t not in ("sigma", "yara", "ioc", "rejected"):
                print(f"  (unknown list type {t!r}; use one of: sigma yara ioc rejected)")
                continue
            cmd_list(SimpleNamespace(type=t))
            continue
        if low == "stats":
            cmd_stats(SimpleNamespace())
            continue
        if low.startswith("validate "):
            cmd_validate(SimpleNamespace(file=raw.split(None, 1)[1].strip()))
            continue
        if low in ("insecure on", "insecure=on"):
            session["insecure"] = True
            print("  TLS verification: OFF (for this session)")
            continue
        if low in ("insecure off", "insecure=off"):
            session["insecure"] = False
            os.environ.pop("RULEFORGE_INSECURE", None)
            print("  TLS verification: ON")
            continue

        kind = _classify_input(raw)
        if kind == "url":
            _interactive_run_fetch(raw, session)
        elif kind == "preset":
            _interactive_run_ingest(raw, session)
        elif kind == "file":
            _interactive_run_convert(raw)
        else:
            print(f"  (unrecognized: {raw!r})")
            print(f"  Try a URL, a file path, or one of: "
                  f"{', '.join(INGEST_PRESETS.keys())}.")
            print(f"  Type 'help' for the full reference.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ruleforge", description="Deterministic detection-content converter")
    # Subcommand is optional — running with no args drops into interactive mode.
    sub = p.add_subparsers(dest="cmd", required=False)

    pf = sub.add_parser("fetch", help="Fetch a URL and convert")
    pf.add_argument("url")
    pf.add_argument("--type", choices=["sigma", "yara", "ioc"])
    pf.add_argument("--dry-run", action="store_true")
    pf.add_argument("--limit", type=int,
                    help="Cap files fetched (only meaningful for tree URLs).")
    pf.add_argument("--filter",
                    help="Substring filter against file paths (tree URLs only).")
    pf.add_argument("--insecure", action="store_true",
                    help="Disable TLS verification (corporate proxies). "
                         "Prefer REQUESTS_CA_BUNDLE env var.")
    pf.set_defaults(func=cmd_fetch)

    pi = sub.add_parser("ingest", help="Run a preset source")
    pi.add_argument("source")
    pi.add_argument("--limit", type=int)
    pi.add_argument("--filter")
    pi.add_argument("--since")
    pi.add_argument("--insecure", action="store_true",
                    help="Disable TLS verification (corporate proxies). "
                         "Prefer REQUESTS_CA_BUNDLE env var.")
    pi.set_defaults(func=cmd_ingest)

    pc = sub.add_parser("convert", help="Convert a local file")
    pc.add_argument("file")
    pc.add_argument("--type", choices=["sigma", "yara", "ioc"])
    pc.add_argument("--dry-run", action="store_true")
    pc.set_defaults(func=cmd_convert)

    pv = sub.add_parser("validate", help="Validate a file already in EaglEye format")
    pv.add_argument("file")
    pv.set_defaults(func=cmd_validate)

    pl = sub.add_parser("list", help="Show output/ contents")
    pl.add_argument("--type", choices=["sigma", "yara", "ioc", "rejected"])
    pl.set_defaults(func=cmd_list)

    ps = sub.add_parser("stats", help="Print summary counts")
    ps.set_defaults(func=cmd_stats)

    pix = sub.add_parser("interactive", help="Interactive prompt (default when no subcommand)")
    pix.set_defaults(func=cmd_interactive)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # No subcommand -> interactive mode.
    if not getattr(args, "func", None):
        return cmd_interactive(args)
    if getattr(args, "insecure", False):
        os.environ["RULEFORGE_INSECURE"] = "1"
        print("[WARN] TLS verification disabled via --insecure. "
              "Prefer setting REQUESTS_CA_BUNDLE to your corp CA bundle.")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
