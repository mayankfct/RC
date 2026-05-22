# RuleForge

**Deterministic detection-content converter.** Fetches Sigma rules, YARA
rules, and IOC feeds from public sources, converts each to EaglEye's
internal schema, validates it, and writes the result to `./output/`.

```
                ┌──────────────────────────────────────────────────┐
SigmaHQ raw ──► │                                                  │
SigmaHQ tree ──►│     ruleforge.py  (single Python file)           │ ──► output/sigma/R-NNN.yml
Neo23x0 tree ──►│                                                  │ ──► output/yara/Y-NNN_<family>.yar
Yara-Rules  ──►│   • detect type   • map fields                    │ ──► output/iocs/<source>.jsonl
abuse.ch    ──►│   • lowercase     • inject MITRE / filesize       │ ──► output/rejected/<file>.reject.txt
CISA KEV    ──►│   • validate      • write to disk                 │
local file  ──►│                                                  │ ──► state.json   (next IDs, dedup hashes)
                └──────────────────────────────────────────────────┘
```

Single file (`ruleforge.py`), three deps (`requests`, `pyyaml`, `plyara`),
no database, no services, no async, no LLM. If a rule can't be cleanly
converted, it goes to `output/rejected/` with a reason — never both,
never neither, every input gets exactly one outcome.

See [`BUILD.md`](BUILD.md) for the original spec and
[`DECISIONS.md`](DECISIONS.md) for every judgment call where this
implementation deviates from a strict reading of `BUILD.md`.

---

## Install

```
pip install -r requirements.txt
```

Python 3.10 or newer.

---

## 30-second start

```bash
# 1. Convert a bundled fixture so you can see what the output looks like
python ruleforge.py convert fixtures/sigma_valid.yml
#   → [OK] R-001 → output/sigma/R-001.yml

# 2. Validate the produced file
python ruleforge.py validate output/sigma/R-001.yml
#   → No issues.

# 3. Pull one real SigmaHQ rule live
python ruleforge.py fetch https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml
#   → [OK] R-002 → output/sigma/R-002.yml

# 4. See what's in output/
python ruleforge.py list
python ruleforge.py stats
```

---

## Interactive mode (the easy way)

Just run with no arguments:

```bash
python ruleforge.py
```

You get a prompt. Paste in anything — a URL, a file path, or a preset
name — and RuleForge auto-detects what to do:

```
RuleForge interactive mode. Type 'help' for options, 'quit' to exit.
Presets: sigmahq, neo23x0, yara-rules, abuse-bazaar, abuse-threatfox, abuse-urlhaus, cisa-kev

ruleforge> https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/.../proc.yml
  → runs `fetch` automatically

ruleforge> fixtures/yara_valid.yar
  → runs `convert` automatically

ruleforge> cisa-kev
  Limit number of items [50]: 100
  Filter substring (blank = no filter) []:
  → runs `ingest cisa-kev --limit 100` automatically

ruleforge> stats
  → shows current corpus counts

ruleforge> insecure on
  TLS verification: OFF (for this session)

ruleforge> quit
```

Built-in commands at the prompt: `help`, `list [type]`, `stats`,
`validate <file>`, `insecure on|off`, `quit` (or `exit` / `q`).

When you give a GitHub tree URL or a preset name, RuleForge asks for
`--limit` and `--filter` interactively (with defaults). For everything
else it just runs with sensible defaults.

The interactive mode is the **default** when you run with no arguments.
The six subcommands below remain for scripting / power users.

## Six CLI commands

### `convert <file>`
Convert a single local file. Auto-detects type from extension and content.

```bash
python ruleforge.py convert path/to/rule.yml         # → output/sigma/R-NNN.yml
python ruleforge.py convert path/to/rule.yar         # → output/yara/Y-NNN_<family>.yar
python ruleforge.py convert path/to/feed.json --type ioc
python ruleforge.py convert path/to/rule.yml --dry-run   # print, don't save
```

A multi-rule `.yar` file produces one output per rule and an aggregated
`[OK-PARTIAL]` summary if some rules fail.

### `fetch <url>`
Pull from any of:
- raw GitHub: `https://raw.githubusercontent.com/owner/repo/branch/path/file.yml`
- blob GitHub: `https://github.com/owner/repo/blob/branch/path/file.yml` (auto-rewritten to raw)
- tree GitHub: `https://github.com/owner/repo/tree/branch/sub/path` (walks the directory)
- tree without subpath: `https://github.com/owner/repo/tree/branch` (walks repo root)
- direct feed URL (`.json`)

```bash
# Single rule
python ruleforge.py fetch https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/.../proc.yml

# Walk a tree with a budget (essential for anonymous use — see "GitHub rate limits")
python ruleforge.py fetch https://github.com/Yara-Rules/rules/tree/master --limit 50 --filter malware

# Force the type if auto-detect guesses wrong
python ruleforge.py fetch https://example.com/feed --type ioc

# Print what would be written without touching disk
python ruleforge.py fetch <url> --dry-run

# Skip TLS verification (corporate proxies)
python ruleforge.py fetch <url> --insecure
```

Bare `github.com/owner/repo` URLs (no `/tree/...`) are explicitly
rejected with a message pointing at the right URL shapes.

### `ingest <source-name>`
Bulk-pull from a preset source. Identical conversion pipeline as
`fetch`, with friendlier flags for big corpora.

```bash
python ruleforge.py ingest sigmahq --limit 100 --filter persistence
python ruleforge.py ingest abuse-bazaar --limit 500
python ruleforge.py ingest cisa-kev --limit 50
```

All ingests honor `--limit`, `--filter` (substring against the path),
and `--since YYYY-MM-DD` (where the source API supports it).

### `validate <file>`
Validate a file already in EaglEye format. Prints `[ERROR]` / `[WARN]`
issues. Exit code 0 if clean (no ERRORs; WARNs still allow exit 0).

```bash
python ruleforge.py validate output/sigma/R-001.yml
python ruleforge.py validate output/yara/Y-001_mimikatz.yar
python ruleforge.py validate path/to/handwritten/rule.yml
```

`validate` is *not* a converter — it expects EaglEye-format input. Pass
upstream Sigma to `convert`, not `validate`.

### `list [--type sigma|yara|ioc|rejected]`
Tree view of `output/`.

```bash
python ruleforge.py list                # all four buckets
python ruleforge.py list --type yara    # just YARA output
python ruleforge.py list --type rejected
```

### `stats`
Counts by type and severity, plus current state-file pointers.

```bash
python ruleforge.py stats
```

---

## Preset sources for `ingest`

| Name              | Source                                            | Auth needed |
|-------------------|---------------------------------------------------|-------------|
| `sigmahq`         | `SigmaHQ/sigma` rules/windows                     | `GITHUB_TOKEN` recommended |
| `neo23x0`         | `Neo23x0/signature-base` yara/                    | `GITHUB_TOKEN` recommended |
| `yara-rules`      | `Yara-Rules/rules` malware/                       | `GITHUB_TOKEN` recommended |
| `abuse-bazaar`    | abuse.ch MalwareBazaar recent samples (1000)      | none        |
| `abuse-threatfox` | abuse.ch ThreatFox recent IOCs                    | none        |
| `abuse-urlhaus`   | abuse.ch URLhaus recent payloads                  | none        |
| `cisa-kev`        | CISA Known Exploited Vulnerabilities catalog      | none        |

---

## Output schema cheat-sheet

### Sigma output (`output/sigma/R-NNN.yml`)

```yaml
id: R-001                                    # auto-allocated, monotonic
title: ...
status: experimental                         # always 'experimental' for imports
description: |-
  <upstream description>

  Imported from <source-name> at <url>. Status: experimental - review before promotion.
  Known limitation: machine-converted; may need tuning.
references:
- <upstream URL>
- <upstream references>
author: 'ruleforge-converter (source: <source-name>)'
date: 'YYYY-MM-DD'
severity: high
mitre:
  primary:
    tactic_id: TA0002
    tactic: execution
    technique_id: T1059.001
    technique: PowerShell
  secondary:                                  # only when upstream has multiple tags
    - { tactic_id: ..., tactic: ..., technique_id: ..., technique: ... }
event_type: ProcessStart                      # one of: ProcessStart, ProcessStop,
                                              #   FileCreate, FileClose, RegSet,
                                              #   RegDelete, NetConnect, DnsQuery, ImageLoad
selection:
  image_path|endswith: \powershell.exe        # field names lower_snake_case
  command_line|contains:                      # string values lowercase
  - ' -enc '
  - ' -encodedcommand '
  file_action: Created                        # ENUM values keep PascalCase
filter:                                       # optional — Shape A (map) or Shape B (list of maps)
- target_path|contains: '\inetcache\'
- parent_image_signed: true
  parent_image_signer|contains|any: ['microsoft windows']
tags:                                         # always includes 'imported' + 'source:<name>'
- imported
- source:fetch
version: 1
revision: 1
dedup_window_seconds: 60
```

### YARA output (`output/yara/Y-NNN_<family>.yar`)

```yara
import "pe"                                   # preserved when upstream uses pe./math./...

/*
 * Y-001  FamilyName
 * <description>
 * Source: <url>
 */
rule Y_001_FamilyName                          # underscores in identifier
{
    meta:
        id          = "Y-001"
        family      = "FamilyName"
        description = "..."
        author      = "ruleforge-converter (source: <source-name>)"
        date        = "YYYY-MM-DD"
        severity    = "critical"
        mitre       = "T1003.001"              # comma-joined technique IDs
        mitre_primary_tactic        = "credential-access"
        mitre_primary_tactic_id     = "TA0006"
        mitre_primary_technique_id  = "T1003.001"
        mitre_primary_technique     = "LSASS Memory"
        mitre_secondary             = "TA0005/T1027/Obfuscated Files or Information"
                                              # secondaries: ';' between entries, '/' within
        reference   = "<url>"

    strings:
        $s1 = "..." ascii wide

    // auto-injected: filesize cap         (only when upstream lacked one)
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of ($s*)
}
```

### IOC output

`output/iocs/malware_bazaar.jsonl` (one JSON object per line):
```json
{"sha256":"...","md5":"...","imphash":"...","verdict":"malicious","family":"LockBit","type":"exe","source":"malware_bazaar","first_seen":"...","last_seen":"...","tags":["..."]}
```

`output/iocs/cisa_kev.jsonl` (CISA-specific shape — CVEs not hashes):
```json
{"cve":"CVE-2024-12345","vendor":"...","product":"...","short_description":"...","date_added":"...","required_action":"...","due_date":"...","known_ransomware_use":true,"source":"cisa_kev"}
```

### Rejection file (`output/rejected/<name>.reject.txt`)

```
SOURCE: <url or local path>
TYPE: sigma | yara | ioc
REASON: <code>
DETAIL: <human-readable explanation>
TIMESTAMP: 2026-05-22T14:23:00Z
---
<original content verbatim>
```

---

## Rejection reason codes

| Code                          | What it means                                                          |
|-------------------------------|------------------------------------------------------------------------|
| `non_endpoint_logsource`      | Sigma logsource was cloud / linux / webserver — out of EaglEye scope   |
| `unmapped_field`              | Sigma field not in the EaglEye mapping table for this event_type       |
| `unsupported_modifier`        | Sigma used `\|base64`, `\|cidr`, `\|wide`, etc.                          |
| `unknown_modifier`            | Sigma used a modifier outside the entire allowlist                     |
| `empty_selection`             | All selection fields got dropped after mapping                         |
| `bad_yaml` / `bad_json`       | Input failed to parse                                                  |
| `empty_content`               | Zero-byte or whitespace-only response                                  |
| `unknown_content`             | Input looks like HTML or other non-rule content                        |
| `mitre_missing`               | (Sigma only with the strict pre-relax path — see permissive notes below)|
| `mitre_technique_unknown`     | Technique ID not in built-in dict AND not in cached catalog            |
| `yara_parse_error`            | plyara couldn't parse the rule (upstream or after re-emission)         |
| `yara_no_structural_anchor`   | Rare — would only fire if condition is completely empty                |
| `yara_single_string`          | YARA `condition: $a` or equivalent — over-fires; needs combination     |
| `yara_disallowed_module`      | YARA uses `cuckoo` / `elf` / `magic` module (not on agent)             |
| `yara_family_missing`         | YARA rule has no `family` meta and rule name didn't yield one          |
| `bad_id_format` / `bad_status` / `bad_severity` / `bad_event_type` / `bad_modifier` / `not_lowercase` / `bad_regex` / `desc_too_short` / `bad_author` / `bad_date` | Validator findings on hand-written rules passed to `validate` |
| `filter_and_trap`             | WARN only — single filter map mixing ≥3 field families                 |
| `mitre_auto_injected`         | WARN — defaulted to `T1027` because upstream had no MITRE              |
| `yara_no_pe_anchor`           | WARN — rule has filesize but no PE/ELF magic; scans every file under cap |
| `yara_filesize_missing`       | WARN — filesize cap was auto-injected                                  |

---

## Workflow recipes

### Recipe 1 — first-time setup, populate a baseline corpus

```powershell
# Set up GitHub auth (lifts rate limit from 60/hr to 5000/hr)
$env:GITHUB_TOKEN = "ghp_yourTokenHere"

# Pull from each source with a small limit first to verify everything works
python ruleforge.py ingest sigmahq      --limit 50  --filter process_creation
python ruleforge.py ingest neo23x0      --limit 50
python ruleforge.py ingest abuse-bazaar --limit 100
python ruleforge.py ingest cisa-kev     --limit 100

# Inspect
python ruleforge.py stats
python ruleforge.py list
```

### Recipe 2 — convert one rule you just found

```bash
# Got a blob URL from a vendor blog or PR?
python ruleforge.py fetch https://github.com/<owner>/<repo>/blob/main/<path>/foo.yml

# Or save it locally and convert
curl -O https://example.com/foo.yml
python ruleforge.py convert foo.yml
```

### Recipe 3 — dry-run preview before committing

```bash
# See what convert would produce, without touching state or disk
python ruleforge.py convert path/to/rule.yml --dry-run
python ruleforge.py fetch <url> --dry-run
```

### Recipe 4 — review rejections to find patterns

```bash
python ruleforge.py list --type rejected
# Open the .reject.txt files — each starts with REASON: <code>
# Filter by reason:
grep -l "REASON: unmapped_field" output/rejected/*.reject.txt
```

### Recipe 5 — reset and start over

```bash
rm -rf output state.json
# mitre_attack.json can stay — it's cached & refreshed weekly
```

### Recipe 6 — promote a rule from `experimental` to `stable`

`status` defaults to `experimental` for all imports. To promote:
1. Hand-edit the YAML: change `status: experimental` → `status: stable`.
2. Re-run `validate` — it'll re-grade with the stable-rule rules.
3. Move the file to your production rules directory (RuleForge doesn't
   manage promotion itself).

---

## MITRE handling

- **Catalog source.** `https://github.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
  is downloaded on first run, cached as `mitre_attack.json` in the
  working directory, and refreshed every 7 days.
- **Built-in fallback.** A built-in dict of ~50 common techniques means
  the converter works offline once the catalog is cached.
- **Auto-injection.** If a rule's upstream lacks MITRE tags entirely,
  RuleForge defaults to **`T1027 — Obfuscated Files or Information`**
  (a broad "unknown malware sample" classification). The output gets:
    - `imported:auto-mitre` extra tag (Sigma) or
    - `mitre_auto_injected` WARN in the convert summary (YARA)
  Override via the `YARA_DEFAULT_MITRE_TECHNIQUE` module constant.
- **Source of truth.** RuleForge always pulls the human-readable name
  from the catalog, so `tactic` and `tactic_id` (and `technique` /
  `technique_id`) are guaranteed consistent in output.

---

## Multi-rule YARA file handling

A single `.yar` file (e.g. SigmaHQ's `APT_APT1.yar`) can contain dozens
of rules. RuleForge:
- Allocates a fresh `Y-NNN` per rule.
- Writes one output file per successful rule.
- Writes a per-rule rejection file (`<basename>_<rule-or-id>.reject.txt`)
  for each rule that fails its checks.
- Prints a `[OK]` or `[REJECT]` line per rule, then an aggregated
  `[OK]` / `[OK-PARTIAL]` / `[REJECT]` summary for the whole file.
- File-level errors (parse failure, disallowed `import "cuckoo"`)
  reject the whole file.

---

## `state.json` reference

```json
{
  "next_sigma_id": 42,            // next R-NNN to allocate
  "next_yara_id": 17,             // next Y-NNN
  "next_ioc_id": 1583,            // next S-NNN (reserved; IOCs use sha256 dedup)
  "seen_hashes": {
    "rules":          ["sha256:..."],   // file-level dedup for sigma/yara
    "malware_bazaar": ["sha256:..."],
    "threatfox":      [],
    "urlhaus":        [],
    "cisa_kev":       ["CVE-..."]
  },
  "ingest_watermarks": {
    "sigmahq":  "2026-05-20T02:00:00Z"
  },
  "mitre_catalog_fetched": "2026-05-15T00:00:00Z"
}
```

Don't hand-edit. Don't delete unless you want IDs to start over and
duplicates to re-process.

---

## Environment knobs

| Variable / flag        | Effect                                                                                          |
|------------------------|-------------------------------------------------------------------------------------------------|
| `GITHUB_TOKEN`         | Personal-access token (no scopes needed for public repos). Lifts the 60 req/hour anonymous rate limit on GitHub tree-walks (`sigmahq`, `neo23x0`, `yara-rules`). Create at https://github.com/settings/tokens. |
| `REQUESTS_CA_BUNDLE`   | Path to your corporate root-CA bundle. **Preferred** workaround for TLS-intercepting proxies — keeps verification on. |
| `RULEFORGE_INSECURE=1` | Disables TLS verification entirely. Same as `--insecure` on the CLI. Use only if you can't get the CA bundle. |
| `--insecure`           | CLI flag on `fetch` / `ingest` — same as `RULEFORGE_INSECURE=1` for that invocation.            |
| `--limit N`            | Cap files fetched (tree URLs / ingest presets).                                                 |
| `--filter <substring>` | Path-substring filter (tree URLs / ingest presets).                                             |
| `--since YYYY-MM-DD`   | (Where the source API supports it — ingest only.)                                               |
| `--dry-run`            | Print conversion output without writing to disk or state.                                       |

---

## Troubleshooting

| Symptom                                                              | Fix                                                                                                                  |
|----------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `GitHub anonymous rate limit hit`                                    | Set `GITHUB_TOKEN` (see above) — anonymous is 60/hr, authenticated is 5000/hr. Or wait an hour. Or use `--limit` + `--filter` to cut API calls. |
| `SSL: CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain` | Corporate TLS-intercepting proxy. Set `REQUESTS_CA_BUNDLE` to your corp root CA (preferred), or pass `--insecure`.    |
| `[REJECT] ... unknown_content`                                       | You probably passed a bare repo URL (`github.com/owner/repo`) or a 404 page. Use a raw/blob/tree URL or `ingest`.       |
| `[REJECT] ... non_endpoint_logsource`                                | Upstream Sigma is for cloud / linux / webserver / proxy — out of EaglEye scope. Expected, not a bug.                |
| `[REJECT] ... unmapped_field`                                        | Upstream Sigma references a field with no EaglEye equivalent (e.g. SAP-specific fields). Expected for non-Windows rules. |
| `[REJECT] ... mitre_technique_unknown`                               | Sigma rule references a technique not in the catalog. Refresh: delete `mitre_attack.json` and re-run.               |
| `[REJECT] ... yara_parse_error: Unknown text X for token of type ID` | The upstream YARA rule has an escape sequence plyara can't round-trip. Hand-edit the affected string and re-run.    |
| `[REJECT] ... yara_single_string`                                    | YARA condition is `$a` or `1 of them` with one string. Add a second indicator string and re-run.                    |
| Filesize cap shows up in YARA output that didn't have one upstream   | Intentional — `// auto-injected: filesize cap`. See `DECISIONS.md`.                                                 |
| `imported:auto-mitre` tag on Sigma output                            | Upstream had no usable `attack.tNNNN` tags; defaulted to `T1027`. Review and refine before promoting.                |
| `[WARN] yara_no_pe_anchor`                                           | Rule has filesize cap but no PE/ELF gate — will scan every file under cap. Add `uint16(0) == 0x5A4D and ...` if Windows-only. |
| `state.json` got corrupted                                           | Delete it. IDs restart at 1 and dedup state is lost (re-imports will re-write).                                     |

---

## Auto-injections — what RuleForge fills in for you

| What's missing upstream         | What RuleForge does                                                                | Surfaced as            |
|---------------------------------|------------------------------------------------------------------------------------|------------------------|
| YARA `filesize` cap             | Injects `and filesize < 50MB` with `// auto-injected: filesize cap` comment        | `[WARN] yara_filesize_missing` |
| YARA PE/ELF anchor              | Nothing (can't guess platform safely) — but doesn't reject either                  | `[WARN] yara_no_pe_anchor`     |
| YARA MITRE tags                 | Defaults to `T1027 Obfuscated Files or Information`                                | `[WARN] mitre_auto_injected`   |
| Sigma `tags:` with no `attack.tNNNN` | Same default `T1027`; adds `imported:auto-mitre` to tags                       | `[WARN] mitre_auto_injected`   |
| Sigma `tags:` as a string (not list) | Coerced to `[<string>]`                                                       | silent                 |
| Sigma `references:` as a string | Coerced to `[<string>]`                                                            | silent                 |
| Sigma upstream `level:` missing | Defaults to `medium`                                                               | silent                 |
| Sigma `file_event` category     | Adds `file_action: Created` (PascalCase enum)                                      | silent                 |
| Sigma `file_change` category    | Adds `file_action: Modified`                                                       | silent                 |
| Sigma `file_delete` category    | Adds `file_action: Deleted`                                                        | silent                 |

---

## Tests

```bash
python test_ruleforge.py
```

61+ offline tests, all against fixtures in `fixtures/`. **No network is
touched.** Run before any change you make.

Test breakdown:
- Validator unit tests (each `check_*` function)
- Sigma converter (valid + several rejection paths + PascalCase enum +
  filter named groups + AND-trap heuristic + multi-line description)
- YARA converter (valid + auto-filesize-injection + single-string
  rejection + Windows-path source URLs + multi-rule files + import
  preservation + production-form MITRE meta + semicolon-joined
  `mitre_secondary`)
- IOC handlers (MalwareBazaar + CISA KEV with dedup verification)
- URL parsing (raw / blob / tree / bare-repo)
- Type detection (extension + content sniff + HTML fallback)
- MITRE extraction (primary + secondary + reject paths)
- Error paths (bad YAML, bad JSON, empty content, unknown content)
- Edge cases (tags-as-string, no MITRE → default, filter_* named
  groups, multi-rule .yar, partial multi-rule, `import "pe"`)

---

## Architecture

- **One file: `ruleforge.py`** (~1500 lines). Read top-to-bottom: paths
  → MITRE data → state → validator → Sigma converter → YARA converter
  → IOC handlers → fetch / URL handling → CLI dispatch.
- **No async, no Click, no Rich.** Stdlib `argparse` + `print`. Three
  third-party deps total. Plain Python you can `cat` and understand.
- **No state outside the working directory.** Everything goes in
  `./output/`, `./state.json`, and `./mitre_attack.json`.

The single-file constraint is deliberate — see BUILD.md.

---

## Notes on the EaglEye schema this targets

- **`auto_action`** is gated on `severity == critical` (production EDR
  rule). RuleForge never sets it on imports (imports are always
  `experimental`). `validate` correctly grades hand-written rules.
- **PascalCase enum values** (`Created`, `Modified`, `Outbound`, `Tcp`,
  `RegSz`, `System`, etc.) — the lowercase-literals validator exempts
  these fields per `RULE_AUTHORING.md` §3.
- **YARA `mitre_secondary`** uses **semicolon-joined**
  `tactic_id/technique_id/name` entries per `rule_schemas.html`.
- **`tactic` must match `tactic_id`** — `validate` catches drift; the
  converter's own output is always consistent (catalog-driven).
- **AND-trap heuristic** — single filter map mixing fields from ≥3
  families gets a WARN.

See [`DECISIONS.md`](DECISIONS.md) for the full cross-references to
[`BUILD.md`](BUILD.md), [`EDR_Rules/RULE_AUTHORING.md`](../EDR_Rules/RULE_AUTHORING.md),
and [`rule_schemas.html`](rule_schemas.html), and for every deviation
from a strict reading of those documents.

---

## What's been verified live

- `fetch <raw github URL>` — pulled a single SigmaHQ rule with
  list-of-maps selection shape, PE-metadata fields dropped, MITRE
  T1560.001 resolved via the cached ATT&CK catalog.
- `fetch <github tree URL>` (`Yara-Rules/rules`, `APT_APT1.yar`) —
  multi-rule file: **65 of 69 rules converted**, 4 cleanly rejected
  (single-string conditions + one plyara escape-sequence edge case).
- `ingest cisa-kev --limit 10` — pulled live, wrote JSONL with proper
  CVE shape.
- TLS interception (corporate proxy) handled via `--insecure` flag with
  clear pointer to the `REQUESTS_CA_BUNDLE` preferred fix.
- Anonymous GitHub rate limiting handled with a clean error message and
  remediation pointer to `GITHUB_TOKEN`.
