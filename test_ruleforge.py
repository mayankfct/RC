"""Offline tests for ruleforge.py — no network required."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import ruleforge as rf

HERE = Path(__file__).parent
FIX = HERE / "fixtures"


def _rebind_paths(root: Path) -> None:
    rf.ROOT = root
    rf.OUTPUT = root / "output"
    rf.SIGMA_DIR = rf.OUTPUT / "sigma"
    rf.YARA_DIR = rf.OUTPUT / "yara"
    rf.IOC_DIR = rf.OUTPUT / "iocs"
    rf.REJECT_DIR = rf.OUTPUT / "rejected"
    rf.STATE_PATH = root / "state.json"
    rf.MITRE_CATALOG_PATH = root / "mitre_attack.json"


class TestSigmaValidator(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = rf.load_mitre_catalog()

    def test_id_format_rejects_bad(self) -> None:
        issues = rf.check_id_format({"id": "BADID"}, "sigma")
        self.assertTrue(any(i.code == "bad_id_format" for i in issues))

    def test_id_format_accepts_good(self) -> None:
        issues = rf.check_id_format({"id": "R-001"}, "sigma")
        self.assertEqual(issues, [])

    def test_status_enum(self) -> None:
        self.assertTrue(rf.check_status_enum({"status": "production"}))
        self.assertEqual(rf.check_status_enum({"status": "experimental"}), [])

    def test_severity_enum(self) -> None:
        self.assertTrue(rf.check_severity_enum({"severity": "extreme"}))
        self.assertEqual(rf.check_severity_enum({"severity": "high"}), [])

    def test_description_min_sentences(self) -> None:
        long = "One. Two. Three sentences here."
        self.assertEqual(rf.check_description_min_sentences({"description": long}), [])
        self.assertTrue(rf.check_description_min_sentences({"description": "Just one."}))

    def test_mitre_block_complete(self) -> None:
        good = {"mitre": {"primary": {"tactic_id": "TA0002", "tactic": "execution",
                                       "technique_id": "T1059", "technique": "X"}}}
        self.assertEqual(rf.check_mitre_block_complete(good), [])
        self.assertTrue(rf.check_mitre_block_complete({"mitre": {}}))

    def test_author_format(self) -> None:
        self.assertEqual(rf.check_author_format({"author": "ruleforge-converter (source: x)"}), [])
        self.assertTrue(rf.check_author_format({"author": "someone"}))

    def test_date_iso(self) -> None:
        self.assertEqual(rf.check_date_iso({"date": "2026-05-21"}), [])
        self.assertTrue(rf.check_date_iso({"date": "21/05/2026"}))


class TestSigmaConverter(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_valid_sigma_converts_cleanly(self) -> None:
        content = (FIX / "sigma_valid.yml").read_bytes()
        summary = rf.convert_one(content, "sigma", "local", "fixtures/sigma_valid.yml",
                                  self.state, self.catalog,
                                  original_filename="sigma_valid.yml")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        out_files = list(rf.SIGMA_DIR.glob("*.yml"))
        self.assertEqual(len(out_files), 1)
        produced = out_files[0].read_text(encoding="utf-8")
        self.assertIn("event_type: ProcessStart", produced)
        self.assertIn("image_path|endswith", produced)
        self.assertIn("command_line|contains", produced)
        self.assertIn("severity: high", produced)
        self.assertIn("T1059.001", produced)
        # Re-validate the produced output
        rule = __import__("yaml").safe_load(produced)
        issues = rf.validate_sigma(rule, self.catalog)
        errors = [i for i in issues if i.severity == rf.ERROR]
        self.assertEqual(errors, [], msg="\n".join(str(i) for i in issues))

    def test_forbidden_modifier_rejects(self) -> None:
        content = (FIX / "sigma_forbidden_modifier.yml").read_bytes()
        summary = rf.convert_one(content, "sigma", "local", "fixtures/sigma_forbidden_modifier.yml",
                                  self.state, self.catalog,
                                  original_filename="sigma_forbidden_modifier.yml")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("unsupported_modifier", summary)
        rej = list(rf.REJECT_DIR.glob("*.reject.txt"))
        self.assertEqual(len(rej), 1)
        body = rej[0].read_text(encoding="utf-8")
        self.assertIn("REASON: unsupported_modifier", body)

    def test_cloud_logsource_rejects(self) -> None:
        content = (FIX / "sigma_cloud_logsource.yml").read_bytes()
        summary = rf.convert_one(content, "sigma", "local", "fixtures/sigma_cloud_logsource.yml",
                                  self.state, self.catalog,
                                  original_filename="sigma_cloud_logsource.yml")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("non_endpoint_logsource", summary)

    def test_sigma_ids_increment(self) -> None:
        content = (FIX / "sigma_valid.yml").read_bytes()
        s1 = rf.convert_one(content, "sigma", "local", "u1", self.state, self.catalog,
                             original_filename="a.yml")
        # different content -> not a duplicate
        content2 = content + b"\n# nudge\n"
        s2 = rf.convert_one(content2, "sigma", "local", "u2", self.state, self.catalog,
                             original_filename="b.yml")
        self.assertIn("R-001", s1)
        self.assertIn("R-002", s2)


class TestYaraConverter(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_valid_yara_converts(self) -> None:
        content = (FIX / "yara_valid.yar").read_bytes()
        summary = rf.convert_one(content, "yara", "local", "fixtures/yara_valid.yar",
                                  self.state, self.catalog, original_filename="yara_valid.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        out_files = list(rf.YARA_DIR.glob("*.yar"))
        self.assertEqual(len(out_files), 1)
        produced = out_files[0].read_text(encoding="utf-8")
        self.assertIn("rule Y_001_Mimikatz", produced)
        self.assertIn('id          = "Y-001"', produced)
        self.assertIn('family      = "Mimikatz"', produced)
        self.assertIn("T1003.001", produced)

    def test_yara_no_filesize_injects_cap(self) -> None:
        content = (FIX / "yara_no_filesize.yar").read_bytes()
        summary = rf.convert_one(content, "yara", "local", "fixtures/yara_no_filesize.yar",
                                  self.state, self.catalog,
                                  original_filename="yara_no_filesize.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        out_files = list(rf.YARA_DIR.glob("*.yar"))
        self.assertEqual(len(out_files), 1)
        produced = out_files[0].read_text(encoding="utf-8")
        self.assertIn("auto-injected: filesize cap", produced)
        self.assertIn("filesize < 50MB", produced)

    def test_yara_with_windows_path_source_url(self) -> None:
        """Regression: backslashes in source_url must not produce invalid YARA escapes."""
        content = (FIX / "yara_valid.yar").read_bytes()
        summary = rf.convert_one(content, "yara", "local",
                                  r"fixtures\yara_valid.yar",
                                  self.state, self.catalog,
                                  original_filename="yara_valid.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)

    def test_yara_no_mitre_gets_default_with_warn(self) -> None:
        """Regression: Yara-Rules-style rules without attack.tNNNN tags used
        to be rejected; per user request they now convert with a default
        MITRE technique and a WARN."""
        src = (
            'rule APT_APT1_NoMitre\n'
            '{\n'
            '    meta:\n'
            '        author      = "Test"\n'
            '        description = "Generic APT marker rule with no MITRE tags."\n'
            '        date        = "2024-01-01"\n'
            '        family      = "APT1"\n'
            '        severity    = "high"\n'
            '    strings:\n'
            '        $a = "marker_alpha" ascii\n'
            '        $b = "marker_beta"  ascii\n'
            '    condition:\n'
            '        2 of them\n'
            '}\n'
        ).encode("utf-8")
        summary = rf.convert_one(src, "yara", "local", "synthetic.yar",
                                  self.state, self.catalog,
                                  original_filename="synthetic.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        self.assertIn("mitre_auto_injected", summary)
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        # Defaulted to T1027 Obfuscated Files or Information
        self.assertIn('mitre       = "T1027"', produced)
        self.assertIn('mitre_primary_technique_id  = "T1027"', produced)

    def test_yara_no_anchor_now_converts_with_warn(self) -> None:
        """Regression: rules with neither magic nor filesize used to be rejected.

        Per the user's request: auto-inject filesize unconditionally, surface a
        WARN noting the missing PE/ELF anchor instead of rejecting.
        """
        content = (FIX / "yara_no_anchor.yar").read_bytes()
        summary = rf.convert_one(content, "yara", "local",
                                  "fixtures/yara_no_anchor.yar",
                                  self.state, self.catalog,
                                  original_filename="yara_no_anchor.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        # The summary should carry the PE-anchor warn.
        self.assertIn("yara_no_pe_anchor", summary)
        # And the rebuilt body should have the injected filesize cap.
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        self.assertIn("auto-injected: filesize cap", produced)
        self.assertIn("filesize < 50MB", produced)

    def test_yara_single_string_rejects(self) -> None:
        content = (FIX / "yara_single_string.yar").read_bytes()
        summary = rf.convert_one(content, "yara", "local", "fixtures/yara_single_string.yar",
                                  self.state, self.catalog,
                                  original_filename="yara_single_string.yar")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("yara_single_string", summary)


class TestIocHandlers(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bazaar_sample(self) -> None:
        data = json.loads((FIX / "bazaar_sample.json").read_text(encoding="utf-8"))
        entries = data["data"]
        c, r, s = rf.process_bazaar_entries(entries, self.state)
        # 5 entries; one has bad sha256 (c... is 65 chars) -> rejected
        self.assertEqual(c, 4)
        self.assertEqual(r, 1)
        out = rf.IOC_DIR / "malware_bazaar.jsonl"
        self.assertTrue(out.exists())
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 4)
        for ln in lines:
            doc = json.loads(ln)
            self.assertEqual(len(doc["sha256"]), 64)
            self.assertEqual(doc["verdict"], "malicious")
            self.assertEqual(doc["source"], "malware_bazaar")

    def test_bazaar_dedup(self) -> None:
        data = json.loads((FIX / "bazaar_sample.json").read_text(encoding="utf-8"))
        rf.process_bazaar_entries(data["data"], self.state)
        c, r, s = rf.process_bazaar_entries(data["data"], self.state)
        self.assertEqual(c, 0)
        self.assertGreater(s, 0)

    def test_cisa_kev_sample(self) -> None:
        data = json.loads((FIX / "cisa_kev_sample.json").read_text(encoding="utf-8"))
        c, r, s = rf.process_cisa_kev_entries(data["vulnerabilities"], self.state)
        self.assertEqual(c, 3)
        out = rf.IOC_DIR / "cisa_kev.jsonl"
        self.assertTrue(out.exists())
        for ln in out.read_text(encoding="utf-8").strip().splitlines():
            doc = json.loads(ln)
            self.assertTrue(doc["cve"].startswith("CVE-"))
        # first entry has knownRansomwareCampaignUse=Known
        first = json.loads(out.read_text(encoding="utf-8").strip().splitlines()[0])
        self.assertTrue(first["known_ransomware_use"])


class TestRuleAuthoringRefinements(unittest.TestCase):
    """Behaviors driven by EDR_Rules/RULE_AUTHORING.md."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_event_emits_pascalcase_file_action(self) -> None:
        sigma = (
            "title: Suspicious DLL Dropped to System32\n"
            "id: 00000000-0000-0000-0000-000000000001\n"
            "status: experimental\n"
            "description: |\n"
            "  Detects DLL drops into the System32 directory by unsigned processes.\n"
            "references:\n"
            "  - https://attack.mitre.org/techniques/T1543/003/\n"
            "author: Sigma Community\n"
            "date: 2024-04-01\n"
            "tags:\n"
            "  - attack.persistence\n"
            "  - attack.t1543.003\n"
            "logsource:\n"
            "  category: file_event\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    TargetFilename|endswith: '.dll'\n"
            "  condition: selection\n"
            "level: high\n"
        ).encode("utf-8")
        summary = rf.convert_one(sigma, "sigma", "local", "synthetic.yml",
                                  self.state, self.catalog,
                                  original_filename="synthetic.yml")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0].read_text(encoding="utf-8")
        self.assertIn("file_action: Created", produced)
        self.assertNotIn("file_action: created", produced)

    def test_filter_and_trap_warns_on_three_families(self) -> None:
        rule = {
            "id": "R-999", "title": "x", "status": "experimental",
            "description": "One. Two. Three.",
            "severity": "high", "author": "ruleforge-converter (source: t)",
            "date": "2026-05-21",
            "mitre": {"primary": {"tactic_id": "TA0002", "tactic": "execution",
                                  "technique_id": "T1059", "technique": "x"}},
            "event_type": "ProcessStart",
            "selection": {"process_name|endswith": "\\bad.exe"},
            "filter": {
                "process_name|endswith": "\\good.exe",
                "target_path|contains": "\\temp\\",
                "dst_ip|startswith": "10.",
                "reg_key|contains": "\\run\\",
            },
        }
        issues = rf.check_sigma_filter_and_trap(rule)
        self.assertTrue(any(i.code == "filter_and_trap" for i in issues))

    def test_filter_list_shape_does_not_false_trip_and_trap(self) -> None:
        rule = {
            "filter": [
                {"process_name|endswith": "\\good.exe"},
                {"target_path|contains": "\\temp\\"},
                {"dst_ip|startswith": "10."},
            ],
        }
        # Each map has 1 family, so no warn even though list spans 3 total.
        issues = rf.check_sigma_filter_and_trap(rule)
        self.assertEqual(issues, [])

    def test_yara_emits_production_mitre_meta_keys(self) -> None:
        content = (FIX / "yara_valid.yar").read_bytes()
        rf.convert_one(content, "yara", "local", "fixtures/yara_valid.yar",
                        self.state, self.catalog, original_filename="yara_valid.yar")
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        self.assertIn('mitre_primary_technique_id  = "T1003.001"', produced)
        self.assertIn('mitre_primary_technique     = "LSASS Memory"', produced)
        self.assertIn('mitre_primary_tactic_id     = "TA0006"', produced)
        self.assertIn('mitre_primary_tactic        = "credential-access"', produced)

    def test_status_enum_drops_deprecated(self) -> None:
        self.assertNotIn("deprecated", rf.STATUS_ENUM)
        self.assertIn("test", rf.STATUS_ENUM)

    def test_auto_action_check_is_severity_based(self) -> None:
        # Critical severity + auto_action = no issues
        ok = {"severity": "critical", "auto_action": "suspend_process"}
        self.assertEqual(rf.check_sigma_auto_action_only_if_critical(ok), [])
        # High severity + auto_action = WARN (downgraded from ERROR because
        # the project owner has chosen to inject auto_action on every import)
        bad = {"severity": "high", "auto_action": "suspend_process"}
        issues = rf.check_sigma_auto_action_only_if_critical(bad)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, rf.WARN)
        self.assertEqual(issues[0].code, "auto_action_non_critical")
        # No auto_action = always OK
        no_action = {"severity": "low"}
        self.assertEqual(rf.check_sigma_auto_action_only_if_critical(no_action), [])

    def test_mitre_tactic_consistency_catches_mismatch(self) -> None:
        bad = {"mitre": {"primary": {
            "tactic_id": "TA0002", "tactic": "credential-access",
            "technique_id": "T1059", "technique": "x",
        }}}
        issues = rf.check_mitre_tactic_consistency(bad)
        self.assertTrue(any(i.code == "mitre_tactic_mismatch" for i in issues))
        good = {"mitre": {"primary": {
            "tactic_id": "TA0002", "tactic": "execution",
            "technique_id": "T1059", "technique": "x",
        }}}
        self.assertEqual(rf.check_mitre_tactic_consistency(good), [])

    def test_sigma_description_uses_literal_block(self) -> None:
        """Multi-line description should render with YAML | not single-quoted style."""
        content = (FIX / "sigma_valid.yml").read_bytes()
        rf.convert_one(content, "sigma", "local", "fixtures/sigma_valid.yml",
                        self.state, self.catalog, original_filename="sigma_valid.yml")
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0].read_text(encoding="utf-8")
        # Look for "description: |" on its own line (literal-block scalar style)
        self.assertIn("description: |", produced)
        self.assertNotIn("description: '", produced)

    def test_sigma_paths_normalized_to_forward_slashes(self) -> None:
        """Windows backslashes in source URLs should be normalized in Sigma output too."""
        content = (FIX / "sigma_valid.yml").read_bytes()
        rf.convert_one(content, "sigma", "local",
                        r"fixtures\sigma_valid.yml",
                        self.state, self.catalog,
                        original_filename="sigma_valid.yml")
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0].read_text(encoding="utf-8")
        self.assertNotIn(r"fixtures\sigma_valid", produced)
        self.assertIn("fixtures/sigma_valid", produced)

    def test_yara_mitre_secondary_uses_semicolon(self) -> None:
        # Build a YARA fixture that yields two techniques
        yara_src = (
            'rule Multi_Technique\n'
            '{\n'
            '    meta:\n'
            '        family    = "MultiThing"\n'
            '        description = "test"\n'
            '        severity  = "high"\n'
            '        tags      = "attack.t1059.001,attack.t1003.001"\n'
            '    strings:\n'
            '        $a = "alpha" ascii\n'
            '        $b = "beta"  ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 1MB and 2 of ($a, $b)\n'
            '}\n'
        ).encode("utf-8")
        summary = rf.convert_one(yara_src, "yara", "local", "synthetic.yar",
                                  self.state, self.catalog, original_filename="synthetic.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        self.assertIn('mitre_secondary             = "', produced)
        # Semicolon separator (rule_schemas.html §mitre §yara), not comma
        self.assertRegex(produced, r'mitre_secondary\s+=\s+"TA\d+/T\d+(\.\d+)?/[^;"]+"')
        # If there are multiple secondaries they're semicolon-separated; for one
        # secondary there's no separator at all, but never a comma between entries.
        sec_line = [ln for ln in produced.splitlines() if "mitre_secondary" in ln][0]
        self.assertNotIn(",T", sec_line)


class TestEdgeCases(unittest.TestCase):
    """Edge cases for real-world / malformed inputs."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ensure_list_helper(self) -> None:
        self.assertEqual(rf._ensure_list(None), [])
        self.assertEqual(rf._ensure_list("x"), ["x"])
        self.assertEqual(rf._ensure_list(["x", "y"]), ["x", "y"])
        self.assertEqual(rf._ensure_list(("a", "b")), ["a", "b"])

    def test_sigma_tags_as_string_not_list(self) -> None:
        """Some upstream Sigma rules ship `tags: attack.t1059` (scalar). Must not crash."""
        sigma = (
            "title: x\n"
            "id: 00000000-0000-0000-0000-000000000099\n"
            "description: Test description sentence one. Sentence two. Sentence three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: attack.t1059\n"  # scalar, not list
            "logsource: {product: windows, category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\powershell.exe'\n"
            "  condition: selection\n"
            "level: medium\n"
        ).encode("utf-8")
        summary = rf.convert_one(sigma, "sigma", "local", "synthetic.yml",
                                  self.state, self.catalog,
                                  original_filename="synthetic.yml")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)

    def test_sigma_no_tags_auto_injects_mitre(self) -> None:
        """Sigma rules without tags get T1027 default + 'imported:auto-mitre' tag."""
        sigma = (
            "title: x\n"
            "id: 00000000-0000-0000-0000-0000000000aa\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "logsource: {product: windows, category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\bad.exe'\n"
            "  condition: selection\n"
            "level: low\n"
        ).encode("utf-8")
        summary = rf.convert_one(sigma, "sigma", "local", "synthetic.yml",
                                  self.state, self.catalog,
                                  original_filename="synthetic.yml")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        self.assertIn("mitre_auto_injected", summary)
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0].read_text(encoding="utf-8")
        self.assertIn("technique_id: T1027", produced)
        self.assertIn("imported:auto-mitre", produced)

    def test_sigma_filter_named_groups(self) -> None:
        """filter_legitimate + filter_microsoft -> list-of-maps (Shape B)."""
        sigma = (
            "title: x\n"
            "id: 00000000-0000-0000-0000-0000000000bb\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: [attack.t1059.001]\n"
            "logsource: {product: windows, category: process_creation}\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\powershell.exe'\n"
            "  filter_msft:\n"
            "    ParentImage|endswith: '\\sccm.exe'\n"
            "  filter_dev:\n"
            "    ParentImage|endswith: '\\code.exe'\n"
            "  condition: selection and not (filter_msft or filter_dev)\n"
            "level: high\n"
        ).encode("utf-8")
        summary = rf.convert_one(sigma, "sigma", "local", "synthetic.yml",
                                  self.state, self.catalog,
                                  original_filename="synthetic.yml")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0].read_text(encoding="utf-8")
        # Should produce filter as a list of two maps
        import yaml as _yaml
        rule = _yaml.safe_load(produced)
        self.assertIsInstance(rule["filter"], list)
        self.assertEqual(len(rule["filter"]), 2)

    def test_empty_content_rejects_cleanly(self) -> None:
        summary = rf.convert_one(b"", "sigma", "local", "empty.yml",
                                  self.state, self.catalog,
                                  original_filename="empty.yml")
        self.assertTrue(summary.startswith("[REJECT]"))
        self.assertIn("empty_content", summary)

    def test_whitespace_only_content_rejects_cleanly(self) -> None:
        summary = rf.convert_one(b"   \n\t\n  ", "yara", "local", "ws.yar",
                                  self.state, self.catalog,
                                  original_filename="ws.yar")
        self.assertTrue(summary.startswith("[REJECT]"))
        self.assertIn("empty_content", summary)

    def test_yara_multi_rule_file(self) -> None:
        """A .yar with two rules should produce two output files."""
        src = (
            'rule First_Rule\n'
            '{\n'
            '    meta:\n'
            '        family    = "FirstFam"\n'
            '        description = "First rule"\n'
            '        severity  = "high"\n'
            '        tags      = "attack.t1059.001"\n'
            '    strings:\n'
            '        $a = "alpha_marker" ascii\n'
            '        $b = "beta_marker"  ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($a, $b)\n'
            '}\n'
            '\n'
            'rule Second_Rule\n'
            '{\n'
            '    meta:\n'
            '        family    = "SecondFam"\n'
            '        description = "Second rule"\n'
            '        severity  = "critical"\n'
            '        tags      = "attack.t1003.001"\n'
            '    strings:\n'
            '        $x = "gamma" ascii\n'
            '        $y = "delta" ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($x, $y)\n'
            '}\n'
        ).encode("utf-8")
        summary = rf.convert_one(src, "yara", "local", "multi.yar",
                                  self.state, self.catalog,
                                  original_filename="multi.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        # Two output files
        out_files = sorted(rf.YARA_DIR.glob("*.yar"))
        self.assertEqual(len(out_files), 2, msg=[f.name for f in out_files])
        names = "\n".join(f.read_text(encoding="utf-8") for f in out_files)
        self.assertIn("Y_001_FirstFam", names)
        self.assertIn("Y_002_SecondFam", names)
        # Both must be re-parseable by plyara
        import plyara as _plyara
        for f in out_files:
            _plyara.Plyara().parse_string(f.read_text(encoding="utf-8"))

    def test_yara_partial_multi_rule(self) -> None:
        """A multi-rule file where one rule is bad should partial-convert."""
        src = (
            'rule Good_Rule\n'
            '{\n'
            '    meta:\n'
            '        family    = "GoodFam"\n'
            '        description = "ok"\n'
            '        severity  = "high"\n'
            '        tags      = "attack.t1059.001"\n'
            '    strings:\n'
            '        $a = "alpha" ascii\n'
            '        $b = "beta" ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 5MB and 2 of ($a, $b)\n'
            '}\n'
            '\n'
            'rule Bad_Single_String\n'
            '{\n'
            '    meta:\n'
            '        family    = "BadFam"\n'
            '        description = "single string condition - should reject"\n'
            '        severity  = "low"\n'
            '        tags      = "attack.t1027"\n'
            '    strings:\n'
            '        $only = "lone_marker" ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 5MB and $only\n'
            '}\n'
        ).encode("utf-8")
        summary = rf.convert_one(src, "yara", "local", "partial.yar",
                                  self.state, self.catalog,
                                  original_filename="partial.yar")
        self.assertTrue(summary.startswith("[OK-PARTIAL]"), msg=summary)
        self.assertIn("1 converted", summary)
        self.assertIn("1 rejected", summary)

    def test_yara_pe_module_import_preserved(self) -> None:
        """When the rule uses `pe.imports(...)`, the import line must survive in output."""
        src = (
            'import "pe"\n'
            '\n'
            'rule UsesPeModule\n'
            '{\n'
            '    meta:\n'
            '        family    = "PEUser"\n'
            '        description = "uses pe module functions"\n'
            '        severity  = "high"\n'
            '        tags      = "attack.t1059.001"\n'
            '    strings:\n'
            '        $a = "marker_a" ascii\n'
            '        $b = "marker_b" ascii\n'
            '    condition:\n'
            '        uint16(0) == 0x5A4D and filesize < 5MB\n'
            '        and pe.number_of_sections > 0\n'
            '        and 2 of ($a, $b)\n'
            '}\n'
        ).encode("utf-8")
        summary = rf.convert_one(src, "yara", "local", "pemod.yar",
                                  self.state, self.catalog,
                                  original_filename="pemod.yar")
        self.assertTrue(summary.startswith("[OK]"), msg=summary)
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        self.assertIn('import "pe"', produced)
        # And the rebuilt rule must re-parse
        import plyara as _plyara
        _plyara.Plyara().parse_string(produced)


class TestAutoActionInjection(unittest.TestCase):
    """auto_action defaults per project owner directive: File→quarantine,
    Network→block, Process/everything-else→suspend."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_sigma(self, category: str) -> bytes:
        return (
            f"title: x\n"
            f"id: 00000000-0000-0000-0000-0000000000{abs(hash(category)) % 100:02d}\n"
            f"description: One. Two. Three.\n"
            f"author: x\n"
            f"date: 2024-01-01\n"
            f"tags: [attack.t1059.001]\n"
            f"logsource: {{product: windows, category: {category}}}\n"
            f"detection:\n"
            f"  selection:\n"
            f"    Image|endswith: '\\bad.exe'\n"
            f"  condition: selection\n"
            f"level: high\n"
        ).encode("utf-8")

    def _convert_and_load(self, content: bytes, name: str) -> dict:
        rf.convert_one(content, "sigma", "local", name, self.state, self.catalog,
                        original_filename=name)
        produced = sorted(rf.SIGMA_DIR.glob("*.yml"))[-1]
        import yaml as _yaml
        return _yaml.safe_load(produced.read_text(encoding="utf-8"))

    def test_process_creation_gets_suspend_process(self) -> None:
        rule = self._convert_and_load(self._make_sigma("process_creation"), "p.yml")
        self.assertEqual(rule["auto_action"], "suspend_process")
        self.assertEqual(rule["event_type"], "ProcessStart")

    def test_file_event_gets_quarantine_file(self) -> None:
        sigma = (
            "title: f\n"
            "id: 00000000-0000-0000-0000-0000000001aa\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: [attack.t1059.001]\n"
            "logsource: {product: windows, category: file_event}\n"
            "detection:\n"
            "  selection: {TargetFilename|endswith: '.exe'}\n"
            "  condition: selection\n"
            "level: high\n"
        ).encode("utf-8")
        rule = self._convert_and_load(sigma, "f.yml")
        self.assertEqual(rule["auto_action"], "quarantine_file")
        self.assertEqual(rule["event_type"], "FileCreate")

    def test_dns_query_gets_block_network(self) -> None:
        sigma = (
            "title: d\n"
            "id: 00000000-0000-0000-0000-0000000002aa\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: [attack.t1071]\n"
            "logsource: {product: windows, category: dns_query}\n"
            "detection:\n"
            "  selection: {QueryName|endswith: '.bad.tld'}\n"
            "  condition: selection\n"
            "level: high\n"
        ).encode("utf-8")
        rule = self._convert_and_load(sigma, "d.yml")
        self.assertEqual(rule["auto_action"], "block_network")
        self.assertEqual(rule["event_type"], "DnsQuery")

    def test_network_connection_gets_block_network(self) -> None:
        sigma = (
            "title: n\n"
            "id: 00000000-0000-0000-0000-0000000003aa\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: [attack.t1071]\n"
            "logsource: {product: windows, category: network_connection}\n"
            "detection:\n"
            "  selection: {DestinationPort: 4444}\n"
            "  condition: selection\n"
            "level: high\n"
        ).encode("utf-8")
        rule = self._convert_and_load(sigma, "n.yml")
        self.assertEqual(rule["auto_action"], "block_network")
        self.assertEqual(rule["event_type"], "NetConnect")

    def test_registry_set_gets_suspend_process(self) -> None:
        sigma = (
            "title: r\n"
            "id: 00000000-0000-0000-0000-0000000004aa\n"
            "description: One. Two. Three.\n"
            "author: x\n"
            "date: 2024-01-01\n"
            "tags: [attack.t1547.001]\n"
            "logsource: {product: windows, category: registry_set}\n"
            "detection:\n"
            "  selection: {TargetObject|contains: '\\Run\\'}\n"
            "  condition: selection\n"
            "level: high\n"
        ).encode("utf-8")
        rule = self._convert_and_load(sigma, "r.yml")
        self.assertEqual(rule["auto_action"], "suspend_process")
        self.assertEqual(rule["event_type"], "RegSet")

    def test_auto_action_tag_set_on_imports(self) -> None:
        rule = self._convert_and_load(self._make_sigma("process_creation"), "p2.yml")
        self.assertIn("imported:auto-action", rule["tags"])

    def test_auto_action_check_is_now_warn_not_error(self) -> None:
        """Used to be ERROR; downgraded to WARN since RuleForge injects on every import."""
        rule = {"severity": "high", "auto_action": "suspend_process"}
        issues = rf.check_sigma_auto_action_only_if_critical(rule)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].severity, rf.WARN)
        self.assertEqual(issues[0].code, "auto_action_non_critical")

    def test_yara_output_has_quarantine_file(self) -> None:
        content = (FIX / "yara_valid.yar").read_bytes()
        rf.convert_one(content, "yara", "local", "fixtures/yara_valid.yar",
                        self.state, self.catalog, original_filename="yara_valid.yar")
        produced = list(rf.YARA_DIR.glob("*.yar"))[0].read_text(encoding="utf-8")
        self.assertIn('auto_action = "quarantine_file"', produced)


class TestInteractiveClassifier(unittest.TestCase):
    """The auto-dispatch logic for the interactive REPL."""

    def test_https_url_classified_as_url(self) -> None:
        self.assertEqual(rf._classify_input("https://github.com/x/y"), "url")
        self.assertEqual(rf._classify_input("http://example.com/feed.json"), "url")
        self.assertEqual(rf._classify_input(
            "https://raw.githubusercontent.com/SigmaHQ/sigma/master/x.yml"), "url")

    def test_preset_name_classified_as_preset(self) -> None:
        for name in ("sigmahq", "neo23x0", "yara-rules", "abuse-bazaar",
                     "abuse-threatfox", "abuse-urlhaus", "cisa-kev"):
            self.assertEqual(rf._classify_input(name), "preset", msg=name)

    def test_existing_file_classified_as_file(self) -> None:
        self.assertEqual(rf._classify_input("fixtures/sigma_valid.yml"), "file")
        self.assertEqual(rf._classify_input("fixtures/yara_valid.yar"), "file")

    def test_garbage_classified_as_unknown(self) -> None:
        self.assertEqual(rf._classify_input("not_a_thing"), "unknown")
        self.assertEqual(rf._classify_input(""), "unknown")
        self.assertEqual(rf._classify_input("   "), "unknown")

    def test_preset_takes_precedence_over_nonexistent_file(self) -> None:
        # Confirms classifier checks INGEST_PRESETS before Path().exists()
        self.assertNotEqual(rf._classify_input("sigmahq"), "unknown")


class TestNoArgsEntersInteractive(unittest.TestCase):
    """Running with no subcommand should call cmd_interactive (not error out)."""

    def test_argparse_does_not_require_subcommand(self) -> None:
        parser = rf.build_parser()
        # Should not raise SystemExit when called with no args
        args = parser.parse_args([])
        self.assertIsNone(getattr(args, "func", None),
                          msg="no-args should leave func unset so main() routes to interactive")


class TestUrlParsing(unittest.TestCase):
    def test_blob_to_raw(self) -> None:
        url = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/proc.yml"
        rewrote = rf.rewrite_blob_to_raw(url)
        self.assertEqual(rewrote,
                         "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/proc.yml")

    def test_raw_passes_through(self) -> None:
        url = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/proc.yml"
        self.assertEqual(rf.rewrite_blob_to_raw(url), url)


class TestDetectType(unittest.TestCase):
    def test_extension_yml(self) -> None:
        self.assertEqual(rf.detect_type(b"", "rule.yml"), "sigma")
        self.assertEqual(rf.detect_type(b"", "rule.yaml"), "sigma")

    def test_extension_yara(self) -> None:
        self.assertEqual(rf.detect_type(b"", "rule.yar"), "yara")

    def test_extension_json(self) -> None:
        self.assertEqual(rf.detect_type(b"", "feed.json"), "ioc")

    def test_sniff_sigma(self) -> None:
        b = b"title: x\nlogsource:\n  product: windows\ndetection:\n  selection: {}"
        self.assertEqual(rf.detect_type(b, "noext"), "sigma")

    def test_sniff_yara(self) -> None:
        b = b"rule MyRule { strings: $a = \"x\" condition: $a }"
        self.assertEqual(rf.detect_type(b, "noext"), "yara")

    def test_sniff_html_returns_unknown(self) -> None:
        """Regression: HTML used to fall through to 'sigma' and crash yaml.safe_load."""
        b = b"<!DOCTYPE html>\n<html lang=\"en\"><head><title>GitHub</title></head></html>"
        self.assertEqual(rf.detect_type(b, "noext"), "unknown")
        b2 = b"<html><body>404</body></html>"
        self.assertEqual(rf.detect_type(b2, "noext"), "unknown")


class TestBareRepoUrlDetection(unittest.TestCase):
    def test_bare_repo_matches(self) -> None:
        self.assertTrue(rf.GH_BARE_REPO_RE.match("https://github.com/Yara-Rules/rules"))
        self.assertTrue(rf.GH_BARE_REPO_RE.match("https://github.com/SigmaHQ/sigma/"))

    def test_tree_url_is_not_bare(self) -> None:
        self.assertFalse(rf.GH_BARE_REPO_RE.match(
            "https://github.com/SigmaHQ/sigma/tree/master/rules/windows"))

    def test_blob_url_is_not_bare(self) -> None:
        self.assertFalse(rf.GH_BARE_REPO_RE.match(
            "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/proc.yml"))


class TestTreeUrlPattern(unittest.TestCase):
    def test_tree_with_subpath(self) -> None:
        m = rf.GH_TREE_RE.match(
            "https://github.com/SigmaHQ/sigma/tree/master/rules/windows")
        self.assertIsNotNone(m)
        owner, repo, ref, path = m.groups()
        self.assertEqual(owner, "SigmaHQ")
        self.assertEqual(repo, "sigma")
        self.assertEqual(ref, "master")
        self.assertEqual(path, "rules/windows")

    def test_tree_without_subpath_matches_repo_root(self) -> None:
        """Regression: /tree/master used to fall through and try to YAML-parse HTML."""
        m = rf.GH_TREE_RE.match("https://github.com/Yara-Rules/rules/tree/master")
        self.assertIsNotNone(m)
        owner, repo, ref, path = m.groups()
        self.assertEqual(owner, "Yara-Rules")
        self.assertEqual(repo, "rules")
        self.assertEqual(ref, "master")
        self.assertIsNone(path)

    def test_tree_with_trailing_slash(self) -> None:
        m = rf.GH_TREE_RE.match("https://github.com/Yara-Rules/rules/tree/master/")
        self.assertIsNotNone(m)
        _, _, ref, path = m.groups()
        self.assertEqual(ref, "master")
        self.assertIsNone(path)


class TestConvertErrorPaths(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile, shutil
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_html_content_rejects_cleanly(self) -> None:
        """Regression: HTML handed to the sigma branch used to crash with a traceback."""
        html = b"<!DOCTYPE html>\n<html><head><style>--x: 4;</style></head></html>\n"
        summary = rf.convert_one(html, "unknown", "fetch", "https://github.com/x/y",
                                  self.state, self.catalog,
                                  original_filename="bare_repo_page.html")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("unknown_content", summary)

    def test_malformed_yaml_rejects_cleanly(self) -> None:
        """Regression: yaml.YAMLError used to propagate as a traceback."""
        bad_yaml = b"title: x\n  bad indent:\n badly: : : :\n"
        summary = rf.convert_one(bad_yaml, "sigma", "fetch", "u",
                                  self.state, self.catalog,
                                  original_filename="bad.yml")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("bad_yaml", summary)

    def test_malformed_json_rejects_cleanly(self) -> None:
        bad_json = b"{not valid json,,,}"
        summary = rf.convert_one(bad_json, "ioc", "fetch", "u",
                                  self.state, self.catalog,
                                  original_filename="bad.json")
        self.assertTrue(summary.startswith("[REJECT]"), msg=summary)
        self.assertIn("bad_json", summary)


class TestMitreExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = rf.load_mitre_catalog()

    def test_extract_primary_and_secondary(self) -> None:
        tags = ["attack.execution", "attack.t1059.001", "attack.t1003.001"]
        m = rf._extract_mitre(tags, self.catalog)
        self.assertEqual(m["primary"]["technique_id"], "T1059.001")
        self.assertEqual(m["primary"]["tactic"], "execution")
        self.assertEqual(len(m["secondary"]), 1)
        self.assertEqual(m["secondary"][0]["technique_id"], "T1003.001")

    def test_no_tags_rejects(self) -> None:
        with self.assertRaises(rf.ConvertError):
            rf._extract_mitre([], self.catalog)

    def test_only_tactic_tags_rejects(self) -> None:
        with self.assertRaises(rf.ConvertError):
            rf._extract_mitre(["attack.execution"], self.catalog)


class TestValidateCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rf_"))
        _rebind_paths(self.tmp)
        self.state = rf.default_state()
        self.catalog = rf.load_mitre_catalog()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_validate_against_produced_sigma(self) -> None:
        content = (FIX / "sigma_valid.yml").read_bytes()
        rf.convert_one(content, "sigma", "local", "u", self.state, self.catalog,
                        original_filename="sigma_valid.yml")
        produced = list(rf.SIGMA_DIR.glob("*.yml"))[0]
        import yaml as _yaml
        rule = _yaml.safe_load(produced.read_text(encoding="utf-8"))
        issues = rf.validate_sigma(rule, self.catalog)
        errors = [i for i in issues if i.severity == rf.ERROR]
        self.assertEqual(errors, [], msg="\n".join(str(i) for i in issues))


if __name__ == "__main__":
    unittest.main(verbosity=2)
