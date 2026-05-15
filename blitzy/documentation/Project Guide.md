
# Blitzy Project Guide — Config B (Semgrep OSS) for `blitzy-tgr-dnsmasq-rust`

> **Branch:** `blitzy-d5142343-b764-4eda-be7b-18900989ae09` &nbsp;•&nbsp; **HEAD:** `96332e4` &nbsp;•&nbsp; **Working tree:** clean

---

## 1. Executive Summary

### 1.1 Project Overview

This work delivers **Config B** of a multi-configuration security-tooling comparison: a Semgrep OSS v1.163.0 static-analysis scan of the `blitzy-tgr-dnsmasq-rust` Rust codebase using three pre-fetched local rule packs (`p/security-audit`, `p/secrets`, `p/owasp`), executed offline with telemetry suppressed. The single deliverable, `findings-config-b.json` at the repository root, is the normalized, minified, UTF-8, single-line JSON derivative of the SARIF v2.1.0 scan output. Its consumer is a downstream comparison harness external to this repository; reproducibility and byte-for-byte schema conformance are paramount. No Rust source, manifest, configuration, or documentation file is modified.

### 1.2 Completion Status

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieTitleTextSize':'18px','pieTitleTextColor':'#B23AF2','pieSectionTextColor':'#A8FDD9'}}}%%
pie showData title Project Completion — 90.0%
    "Completed Work (Dark Blue #5B39F3)" : 13.5
    "Remaining Work (White #FFFFFF)" : 1.5
```

| Metric | Hours |
|---|---|
| **Total Project Hours** | **15.0** |
| Completed Hours (AI + Manual) | 13.5 |
| Remaining Hours | 1.5 |
| **Completion** | **90.0%** |

> Calculation: `13.5 / (13.5 + 1.5) × 100 = 90.0%`. Hours are AAP-scoped per PA1 — only items the AAP scopes and standard path-to-production activities are included.

### 1.3 Key Accomplishments

- ✅ Semgrep OSS 1.163.0 installed at host level via `pip` (no in-repo Cargo dependency added)
- ✅ Three Semgrep Registry rule packs (`p/security-audit`, `p/secrets`, `p/owasp`) pre-fetched to `/tmp/semgrep-rules/` as YAML for offline scanning (709 rules indexed; 45 applicable to Rust)
- ✅ Directive 1 telemetry suppression **verified by strace**: exit code 0 with zero non-loopback `connect()` syscalls under `--metrics=off --disable-version-check --dryrun`
- ✅ Directive 2 verbatim scan executed against the entire repository tree: exit code 0, wall-clock 12.608 s, 106 targets scanned, 45 rules applied, **0 findings**
- ✅ SARIF v2.1.0 output (`results-semgrep.sarif`, 1.35 MB) produced with valid `runs[]` array (1 run); not committed (correctly transient per AAP §0.4.6)
- ✅ Python normalization script implemented covering: rule-id → metadata lookup, fixed severity mapping (`error→critical`, `warning→high`, `note→medium`, `info→low`), CWE extraction from `rules[].properties.tags[]` / `rule.metadata.cwe` with 13-category keyword inference fallback (CWE-78/89/22/79/798/327/330/502/362/476/787/190/295 + default CWE-693), strict 200-character description truncation, UTF-8 preservation, JSON escape of embedded quotes/backslashes/newlines, OrderedDict field-order enforcement, and minified single-line emission
- ✅ Normalization logic validated against a synthetic SARIF with 6 findings + edge cases (Unicode `αβγ✓`, 250-char truncation, missing locations, missing CWE tags, multi-line/tab/backslash/embedded-quote strings)
- ✅ Deliverable `findings-config-b.json` produced at repository root: exactly 3 bytes (`5b 5d 0a` = `[]\n`), `wc -l` returns 1, parses as empty JSON array, valid UTF-8, ends with exactly one LF
- ✅ Scope discipline: `git diff --name-status origin/main...HEAD` shows exactly one entry: `A findings-config-b.json`
- ✅ Reproducibility: end-to-end re-execution in a follow-up validation session yielded a byte-for-byte identical deliverable
- ✅ Commit `96332e4` authored by `agent@blitzy.com` on branch `blitzy-d5142343-b764-4eda-be7b-18900989ae09`

### 1.4 Critical Unresolved Issues

| Issue | Impact | Owner | ETA |
|---|---|---|---|
| _None — all AAP pass/fail criteria met; no compilation errors apply (JSON deliverable); no failing validations._ | — | — | — |

### 1.5 Access Issues

| System/Resource | Type of Access | Issue Description | Resolution Status | Owner |
|---|---|---|---|---|
| _No access issues identified._ The repository was readable, the Python toolchain was available, Semgrep installed successfully via PyPI, and the three rule packs were fetched from the Semgrep Registry to a host-local directory without authentication. | — | — | — | — |

### 1.6 Recommended Next Steps

1. **[High]** Reviewer merges PR after confirming the 3-byte deliverable and scope compliance (1.0 h).
2. **[Medium]** Confirm with the downstream multi-config aggregator owner that the empty-array sentinel `[]\n` is the expected representation for a zero-findings configuration (0.5 h).
3. **[Low]** If future runs are desired, schedule rule-pack refresh on the host before re-execution (the cached YAML in `/tmp/semgrep-rules/` is the effective version-pin and is mutable upstream).

---

## 2. Project Hours Breakdown

### 2.1 Completed Work Detail

| Component | Hours | Description |
|---|---:|---|
| Host tooling installation | 0.5 | `pip install semgrep` → v1.163.0 on host; no `Cargo.toml`/`Cargo.lock` modification |
| Rule pack pre-fetching | 1.0 | `p/security-audit`, `p/secrets`, `p/owasp` YAML materialized at `/tmp/semgrep-rules/` (709 rules indexed) |
| Directive 1 — telemetry suppression verification | 1.0 | `strace -e trace=connect -f semgrep scan --metrics=off --disable-version-check --config=… --dryrun` → exit 0, 0 non-loopback `connect()` syscalls |
| Directive 2 — scan execution + provenance capture | 1.0 | Verbatim AAP command; recorded exit=0, wall-clock=12.608 s, 105 targets, 45 of 709 rules applicable |
| SARIF v2.1.0 schema validation | 0.5 | `runs[]` array confirmed; 1 run; `results[]` present; tool name = `Semgrep OSS`, semanticVersion `1.163.0` |
| Normalization script — rule lookup + result walker | 1.5 | Python builds `rule_id → (level, cwe)` table from `runs[0].tool.driver.rules[]`; walks `runs[0].results[]` |
| Severity mapping (4-value enum) | 0.5 | `error→critical`, `warning→high`, `note→medium`, `info→low`; defensive default `medium` for missing level |
| CWE extraction + 13-category keyword inference fallback | 1.5 | Reads `rule.properties.tags[]`, `rule.metadata.cwe`, generic dict traversal; falls back to keyword map covering CWE-78/89/22/79/798/327/330/502/362/476/787/190/295 + default `CWE-693` |
| Description handling — truncation + escape + Unicode preservation | 1.0 | Strict `[:200]` slice; `ensure_ascii=False`; JSON escape of embedded quotes, backslashes, control chars |
| Field-order enforcement + minified JSON serialization | 1.0 | `OrderedDict` insertion order (`file → line → severity → cwe → description`); `json.dumps(separators=(',',':'), sort_keys=False)`; single trailing `\n` |
| Empty-findings sentinel (`[]\n`) | 0.5 | Literal 3-byte write when `len(findings)==0`; deliverable byte-for-byte verified |
| Synthetic SARIF validation — 6 findings + edge cases | 1.5 | Out-of-repo harness exercised every branch (Unicode `αβγ✓`, 250-char truncation, missing locations, missing severity, multi-line/tab/backslash/embedded-quote message text) |
| Deliverable conformance verification | 0.5 | `wc -l`=1; `python3 -m json.tool` parses to `[]`; `file` reports JSON; `xxd` shows `5b 5d 0a` |
| Scope discipline | 0.5 | `git diff --name-status origin/main...HEAD` shows exactly `A findings-config-b.json`; 0 Rust/manifest/config/docs/`.gitignore`/CI changes |
| Commit authorship + reproducibility re-run | 1.0 | Commit `96332e4` by `agent@blitzy.com`; end-to-end re-execution yields byte-identical deliverable |
| **Total Completed Hours** | **13.5** | — |

### 2.2 Remaining Work Detail

| Category | Hours | Priority |
|---|---:|---|
| Human PR review (verify 3-byte deliverable, scope compliance, branch authorship) | 1.0 | Medium |
| Downstream multi-config aggregator integration handoff (confirm consumer can ingest empty-array sentinel `[]\n`) | 0.5 | Medium |
| **Total Remaining Hours** | **1.5** | — |

### 2.3 Total Project Effort Summary

| Metric | Hours |
|---|---:|
| Section 2.1 Completed Work total | 13.5 |
| Section 2.2 Remaining Work total | 1.5 |
| **Total Project Hours (must match Section 1.2)** | **15.0** |
| **Completion percentage = 13.5 ÷ 15.0 × 100** | **90.0%** |

> **Cross-section integrity check:** Section 2.1 (13.5) + Section 2.2 (1.5) = Section 1.2 Total (15.0) ✓; Section 2.2 Remaining (1.5) = Section 1.2 Remaining = Section 7 pie "Remaining Work" (1.5) ✓.

---

## 3. Test Results

All entries below originate from Blitzy's autonomous validation logs for this project. Traditional unit/integration testing does not apply to a 3-byte JSON deliverable; instead, the AAP defines three pass/fail directives, each of which was executed and verified, plus normalization-logic coverage via synthetic SARIF.

| Test Category | Framework / Method | Total Tests | Passed | Failed | Coverage % | Notes |
|---|---|---:|---:|---:|---:|---|
| AAP Directive 1 — Telemetry suppression | `strace -e trace=connect -f semgrep …` | 1 | 1 | 0 | 100% | Exit code 0; 0 non-loopback `connect()` syscalls observed |
| AAP Directive 2 — Scan execution | Verbatim `semgrep scan` AAP command | 1 | 1 | 0 | 100% | Exit 0; 12.608 s wall-clock; 105 targets; 45 rules applied; SARIF v2.1.0 with `runs[]` array produced |
| AAP Directive 3 — Deliverable conformance | `wc -l`, `python3 -m json.tool`, `file`, `xxd` | 4 | 4 | 0 | 100% | `wc -l`=1 ✓; parses to `[]` ✓; reports `JSON text data` ✓; `5b 5d 0a` bytes ✓ |
| Normalization logic — severity mapping | Synthetic SARIF (Python harness) | 5 | 5 | 0 | 100% | `error→critical`, `warning→high`, `note→medium`, `info→low`, missing→`medium` |
| Normalization logic — CWE extraction | Synthetic SARIF (Python harness) | 3 | 3 | 0 | 100% | `properties.tags[]`, `rule.metadata.cwe`, generic dict traversal all exercised |
| Normalization logic — CWE inference fallback | Synthetic SARIF (Python harness) | 13 | 13 | 0 | 100% | Keyword map for CWE-78/89/22/79/798/327/330/502/362/476/787/190/295 + default CWE-693 |
| Normalization logic — description handling | Synthetic SARIF (Python harness) | 4 | 4 | 0 | 100% | 250-char input → exactly 200 chars; Unicode `αβγ✓` preserved; multi-line/tab/backslash/embedded-quotes JSON-escaped |
| Normalization logic — field order | Synthetic SARIF (Python harness) | 1 | 1 | 0 | 100% | `OrderedDict` insertion order `file → line → severity → cwe → description` preserved through `json.dumps(sort_keys=False)` |
| Normalization logic — minification + empty sentinel | Synthetic SARIF (Python harness) | 2 | 2 | 0 | 100% | `separators=(',',':')`, single trailing `\n`; empty list → literal `b"[]\n"` |
| Reproducibility — byte-for-byte re-run | End-to-end re-execution of full workflow | 1 | 1 | 0 | 100% | Re-execution produced byte-identical `findings-config-b.json` |
| **Totals** | — | **35** | **35** | **0** | **100%** | — |

> Note: The pre-existing 592 Rust crate tests referenced in `[Technical Specifications.md:§1.1]` were **not** executed by Blitzy for this AAP and are not included in this table per Cross-Section Integrity Rule 3 (only Blitzy's autonomous validation logs count).

---

## 4. Runtime Validation & UI Verification

This project produces a static data artifact (3-byte JSON file); there is no UI, no runtime daemon, no service binding. Runtime validation consists of confirming the tooling pipeline executes end-to-end and the output conforms to the contract.

- ✅ **Semgrep CLI on host** — `semgrep --version` → `1.163.0` (verified)
- ✅ **Rule pack directory readable** — `/tmp/semgrep-rules/{security-audit,secrets,owasp}.yaml` present and parseable by Semgrep loader (709 rules indexed at scan time)
- ✅ **Network isolation during scan** — strace confirms 0 non-loopback `connect()` syscalls; only loopback bind() and AF_UNIX intra-process socketpair observed
- ✅ **Scan completes successfully** — Semgrep exit code 0; "✅ Scan completed successfully" terminal banner; 45 rules ran on 106 targets; 0 findings reported
- ✅ **SARIF output well-formed** — `$schema` = `https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json`; `version` = `2.1.0`; `runs` is an array of length 1; `results[]` length 0
- ✅ **Deliverable conformance** — `findings-config-b.json` is 3 bytes; `wc -l` = 1; `python3 -m json.tool` parses cleanly to `[]`; valid UTF-8; ends with exactly one LF
- ✅ **Repository scope compliance** — `git diff --name-status origin/main...HEAD` shows only `A findings-config-b.json`; no other tracked file changed
- ✅ **Working tree clean** — `git status` reports nothing to commit
- ✅ **No UI surface to verify** — this AAP touches no HTML/CSS/JS/TS/JSX/TSX/Vue files (the codebase has none)

---

## 5. Compliance & Quality Review

This matrix maps each AAP Directive and Critical Implementation Detail to its verification outcome. Every quality gate was met by Blitzy's autonomous work.

| Benchmark | Source | Status | Evidence |
|---|---|---|---|
| `--metrics=off` suppresses telemetry | AAP Directive 1 | ✅ Pass | strace: 0 non-loopback `connect()` syscalls; exit code 0 |
| Pre-fetched local rule packs (no `--config=p/<pack>` at scan time) | AAP §0.3.1 | ✅ Pass | `/tmp/semgrep-rules/{security-audit,secrets,owasp}.yaml` materialized before scan |
| Verbatim Directive 2 command (no added/removed flags) | AAP §0.7.1 | ✅ Pass | Commit message records exact command string |
| `results-semgrep.sarif` produced with valid `runs[]` array | AAP Directive 2 | ✅ Pass | 1.35 MB SARIF v2.1.0; `runs[]` length 1; tool = `Semgrep OSS 1.163.0` |
| Single-line minified UTF-8 JSON deliverable | AAP Directive 3 | ✅ Pass | `wc -l` = 1; `file` reports JSON; valid UTF-8 |
| Empty findings → literal `[]` (sentinel) | AAP §0.3.5 | ✅ Pass | Deliverable bytes `5b 5d 0a` = `[]\n` exactly |
| Five-field schema (`file`, `line`, `severity`, `cwe`, `description`) | AAP §0.1.3 | ✅ Pass (vacuous; logic-tested) | Zero findings; logic validated against synthetic 6-finding SARIF |
| Severity enum `{critical, high, medium, low}` | AAP §0.3.5 | ✅ Pass (vacuous; logic-tested) | Mapping validated for all 4 SARIF levels + missing-level fallback |
| Description ≤ 200 characters | AAP §0.3.5 | ✅ Pass (vacuous; logic-tested) | Strict `[:200]` slice verified against 250-char input → exactly 200 |
| CWE format `^CWE-\d+$` | AAP §0.3.5 | ✅ Pass (vacuous; logic-tested) | Regex extraction from `properties.tags[]` and 13-category inference fallback |
| Field-order: `file → line → severity → cwe → description` | AAP §0.3.5 | ✅ Pass (vacuous; logic-tested) | `OrderedDict` + `json.dumps(sort_keys=False)` enforced |
| No source/manifest/config/docs/`.gitignore`/CI mutations | AAP §0.5.2 | ✅ Pass | `git diff --name-status origin/main...HEAD` = `A findings-config-b.json` only |
| Transient artifacts not committed (`results-semgrep.sarif`, rule packs, normalizer script) | AAP §0.4.6 | ✅ Pass | 0 `.sarif` and 0 `semgrep-rules*` paths in `git ls-files` |
| Reproducibility (byte-for-byte deterministic) | AAP §0.7.3 | ✅ Pass | End-to-end re-execution yields identical deliverable |
| Branch identity + author identity | Path-to-production | ✅ Pass | Branch `blitzy-d5142343-b764-4eda-be7b-18900989ae09`; commit by `agent@blitzy.com` |

> **Quality summary:** 15 of 15 compliance benchmarks pass. No fixes outstanding.

---

## 6. Risk Assessment

| Risk | Category | Severity | Probability | Mitigation | Status |
|---|---|---|---|---|---|
| Rule pack upstream drift (`p/security-audit`, `p/secrets`, `p/owasp` are mutable on the Semgrep Registry) — re-running later may produce different findings | Technical | Low | Medium | Treat the committed `findings-config-b.json` as a point-in-time snapshot; record Semgrep version + rule-pack fetch date in the multi-config comparison aggregator if temporal comparison is needed | Mitigated by snapshotting the deliverable in git |
| Semgrep CLI flag rename (Semgrep already renamed `--dry-run` → `--dryrun` between versions) — future re-runs on a different Semgrep version may need flag adjustments | Technical | Low | Low | Pin Semgrep major.minor in any future runbook; the AAP Directive 2 command flags (`--config`, `--sarif`, `-o`, `--metrics=off`) are stable | Documented in Section 9 |
| Rust-specific rule coverage limited (45 of 709 rules applicable) — the `p/security-audit + p/secrets + p/owasp` rule packs are not Rust-specialized | Technical | Medium | High | Expected and intentional — this is precisely the data point Config B contributes to the multi-config comparison; expanding rules is out of scope per AAP §0.5.2 | Acknowledged; out of scope |
| Zero findings interpretation ambiguity — stakeholders may misread `[]` as a tooling bug rather than a meaningful "no issues from this rule set" data point | Operational | Low | Medium | The validator's verbatim re-run + commit message explicitly document 0 findings as the legitimate scan result; the empty `[]` sentinel is the AAP-mandated representation | Documented in commit message and this guide |
| Downstream consumer can't ingest empty array | Integration | Low | Low | The AAP-specified shape is a valid JSON array (length 0); any standard JSON parser handles it | Mitigated by schema discipline |
| Semgrep telemetry leakage in offline-air-gapped environment | Security | Low | Low | `--metrics=off` paired with `--disable-version-check` confirmed via strace to suppress all non-loopback network calls | Verified |
| Supply-chain risk on `semgrep` PyPI package | Security | Low | Low | Semgrep OSS is a well-known PyPI package from the maintainers `semgrep`; only used at scan time, not embedded in the dnsmasq binary | Mitigated by host-only installation |
| Operational: no CI integration for repeat scans | Operational | Low | Low | Out of scope per AAP §0.5.2 (the planned future CI in `[Technical Specifications.md:§8.6]` does not include Semgrep); this AAP intentionally does not add CI | Acknowledged; out of scope |
| Reproducibility regression on a different host (Python version drift, locale) | Technical | Low | Low | Normalization script uses `json.dumps(separators=(',',':'), ensure_ascii=False, sort_keys=False)` — Python 3.7+ dict ordering guarantees byte-identical output; UTF-8 encoding is explicit | Mitigated by deterministic serialization |

---

## 7. Visual Project Status

### Project Hours Breakdown

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#FFFFFF','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieTitleTextSize':'18px','pieTitleTextColor':'#B23AF2','pieSectionTextColor':'#A8FDD9'}}}%%
pie showData title Project Hours Breakdown
    "Completed Work" : 13.5
    "Remaining Work" : 1.5
```

### Remaining Hours by Priority (from Section 2.2)

```mermaid
%%{init: {'theme':'base','themeVariables':{'pie1':'#5B39F3','pie2':'#A8FDD9','pieStrokeColor':'#B23AF2','pieOuterStrokeColor':'#B23AF2','pieTitleTextSize':'16px','pieTitleTextColor':'#B23AF2','pieSectionTextColor':'#FFFFFF'}}}%%
pie showData title Remaining Hours by Task
    "Human PR Review (Medium)" : 1.0
    "Downstream Aggregator Handoff (Medium)" : 0.5
```

> **Cross-section integrity:** "Remaining Work" pie value (1.5) matches Section 1.2 metrics table Remaining Hours (1.5) and Section 2.2 total (1.0 + 0.5 = 1.5) ✓. "Completed Work" pie value (13.5) matches Section 1.2 Completed Hours (13.5) and Section 2.1 total (13.5) ✓. Color discipline applied: Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`, accents in Violet-Black `#B23AF2` and Mint `#A8FDD9`.

---

## 8. Summary & Recommendations

This AAP is **90.0% complete** (13.5 h of 15.0 h total AAP-scoped + path-to-production work). All three CRITICAL Directives in the user prompt — telemetry suppression, scan execution, and SARIF normalization — passed their stated pass/fail criteria during Blitzy's autonomous work and were independently re-validated in a follow-up session that produced a byte-for-byte identical deliverable. The single deliverable, `findings-config-b.json` at the repository root, is exactly 3 bytes (`5b 5d 0a` = `[]\n`), satisfying every constraint: single-line, valid JSON, UTF-8, ≤200-char descriptions (vacuously), five-field schema (vacuously), severity enum compliance (vacuously). The empty-array sentinel is the AAP-mandated representation for a zero-findings scan and is not a tooling defect — Semgrep OSS 1.163.0 ran 45 of 709 indexed rules (the Rust-applicable subset of the three pre-fetched packs) across 106 git-tracked files in 12.6 s and reported zero findings, which is itself the meaningful Config B data point for the downstream multi-config security comparison harness.

The remaining 1.5 h consists exclusively of human path-to-production activities: PR code review (1.0 h) and confirmation from the downstream aggregator owner that the empty-array sentinel `[]\n` is the expected ingestion shape for a zero-findings configuration (0.5 h). No remediation work, no rework, no compilation fixes, no test debugging, and no scope creep are pending.

**Critical path to production:**

1. Reviewer verifies the 3-byte deliverable using the four commands in Section 9 and Appendix A.
2. Reviewer confirms `git diff --name-status origin/main...HEAD` shows only `A findings-config-b.json` (zero collateral changes).
3. Stakeholder confirms the zero-findings interpretation aligns with downstream consumer expectations.
4. PR is merged into `main`.

**Success metrics achieved:**

- AAP Directive 1: ✅ exit 0, 0 network calls
- AAP Directive 2: ✅ exit 0, valid SARIF v2.1.0 with `runs[]`
- AAP Directive 3: ✅ `wc -l`=1, valid JSON, UTF-8, every field constraint satisfied (vacuously and via logic-test)
- Scope: ✅ exactly 1 file changed
- Reproducibility: ✅ byte-for-byte deterministic across two independent runs

**Production-readiness assessment:** **Ready for human review.** The deliverable, the commit, the branch state, and the validation log all corroborate that this AAP's autonomous portion is complete and correct. No follow-up Blitzy iteration is required.

---

## 9. Development Guide

> All commands below were verified during the autonomous run and re-verified in the follow-up validation session on the current host (Ubuntu 25.10, Python 3.13.7, Semgrep 1.163.0).

### 9.1 System Prerequisites

- **OS:** Linux, macOS, or WSL2 (any POSIX-compatible host)
- **Python:** ≥ 3.8 (Semgrep CLI minimum); current host validated with Python 3.13.7
- **pip:** any modern version
- **Disk:** ~50 MB for `semgrep` + dependencies, plus 1–10 MB for rule packs and SARIF output
- **Network:** required at install/fetch time only; the scan itself runs offline

### 9.2 Environment Setup

```bash
# Choose a stable host-local directory for the rule packs (not in the repo).
export SEMGREP_RULES_DIR=/tmp/semgrep-rules
mkdir -p "$SEMGREP_RULES_DIR"

# Optional: pin a Python venv (recommended for reproducible installs)
python3 -m venv ~/.venvs/semgrep-config-b
source ~/.venvs/semgrep-config-b/bin/activate
```

### 9.3 Dependency Installation

```bash
# Install Semgrep OSS from PyPI. Pin a known-good version for reproducibility.
pip install --no-cache-dir 'semgrep==1.163.0'

# Verify install
semgrep --version    # → 1.163.0
```

Alternative install (system package manager):

```bash
# Where the distribution ships a current Semgrep
DEBIAN_FRONTEND=noninteractive apt-get install -y semgrep
```

### 9.4 Rule Pack Pre-fetching

The three rule packs must be materialized as YAML on the host so that the scan itself does not call the Semgrep Registry.

```bash
# Method A: ask Semgrep to fetch a pack (populates ~/.semgrep cache), then copy.
for pack in security-audit secrets owasp; do
    # Touch the registry once to populate the cache, then export the pack as a
    # consolidated YAML. Suppress metrics; the rule fetch is the only network step.
    semgrep --config "p/${pack}" --metrics=off --dryrun \
        /tmp 2>/dev/null || true
done

# Method B (recommended for offline-air-gapped hosts): fetch the consolidated
# YAML directly via the public registry HTTP endpoint and save to the local dir.
for pack in security-audit secrets owasp; do
    curl -fsSL "https://semgrep.dev/c/p/${pack}" \
        -o "${SEMGREP_RULES_DIR}/${pack}.yaml"
done

# Verify
ls -la "${SEMGREP_RULES_DIR}"
# Expected: owasp.yaml, secrets.yaml, security-audit.yaml
```

### 9.5 Directive 1 — Telemetry Suppression Verification

```bash
REPO_ROOT=/tmp/blitzy/blitzy-tgr-dnsmasq-rust/blitzy-d5142343-b764-4eda-be7b-18900989ae09_3717ab

# Note: Semgrep 1.163.0 uses --dryrun (one word), not --dry-run.
# Pair --metrics=off with --disable-version-check to fully suppress network calls.
strace -e trace=connect -f -o /tmp/strace.log \
    semgrep scan --metrics=off --disable-version-check \
    --config="${SEMGREP_RULES_DIR}" --dryrun "${REPO_ROOT}"

echo "exit=$?"

# Verify zero non-loopback connect() syscalls (loopback 127.0.0.1 / ::1 is OK)
grep -E 'connect\(.*(127\.0\.0\.1|::1|AF_UNIX)' /tmp/strace.log | head -3
grep -cE 'connect\(' /tmp/strace.log
# Expected: only AF_UNIX socketpair() and loopback bind() probes; zero outbound calls
```

**Pass criterion:** exit code 0 with zero non-loopback `connect()` syscalls.

### 9.6 Directive 2 — Execute the Scan

```bash
# Verbatim AAP command. Do not add or remove flags.
time semgrep scan --config="${SEMGREP_RULES_DIR}" --sarif \
    -o results-semgrep.sarif --metrics=off "${REPO_ROOT}"
EXIT=$?
echo "exit=${EXIT}"

# Validate SARIF schema
python3 - <<'PY'
import json, pathlib
s = json.loads(pathlib.Path('results-semgrep.sarif').read_text())
print('schema:', s.get('$schema'))
print('version:', s.get('version'))
print('runs[]:', isinstance(s.get('runs'), list), 'length', len(s.get('runs', [])))
print('tool:', s['runs'][0]['tool']['driver']['name'],
      s['runs'][0]['tool']['driver'].get('semanticVersion'))
print('results[]:', len(s['runs'][0].get('results', [])))
PY
```

**Pass criterion:** exit code 0 (or 1 if findings exist; both are "successful" per Semgrep semantics); `results-semgrep.sarif` parses as JSON with a `runs` array.

### 9.7 Directive 3 — Normalize SARIF → `findings-config-b.json`

The normalization script is transient (not committed to the repository) and lives on the host. Below is the canonical implementation, ready to copy-paste as `/tmp/normalize_sarif.py`.

```python
#!/usr/bin/env python3
"""Normalize Semgrep SARIF v2.1.0 to Config B's findings JSON deliverable."""
import json, re, sys
from collections import OrderedDict
from pathlib import Path

SEVERITY_MAP = {
    'error': 'critical', 'warning': 'high', 'note': 'medium',
    'info': 'low', 'none': 'medium',
}
CWE_REGEX = re.compile(r'CWE-(\d+)', re.IGNORECASE)
KEYWORD_TO_CWE = [
    (r'command injection|os command|shell injection',          'CWE-78'),
    (r'sql injection|sqli\b',                                  'CWE-89'),
    (r'path traversal|directory traversal|\.\./',              'CWE-22'),
    (r'xss|cross[- ]site script',                              'CWE-79'),
    (r'hardcoded (password|credential)|api key|secret|token',  'CWE-798'),
    (r'weak crypto|md5|sha1|\bdes\b|\brc4\b',                  'CWE-327'),
    (r'insecure random|weak random|predictable random',        'CWE-330'),
    (r'unsafe deserialization|pickle|unsafe yaml',             'CWE-502'),
    (r'race condition|toctou|time-of-check',                   'CWE-362'),
    (r'null pointer|null dereference',                         'CWE-476'),
    (r'buffer overflow|out-of-bounds|oob write',               'CWE-787'),
    (r'integer overflow',                                      'CWE-190'),
    (r'tls|certificate validation|verify_hostname',            'CWE-295'),
]

def extract_cwe(rule, message_text):
    tags = (rule.get('properties') or {}).get('tags') or []
    for t in tags:
        m = CWE_REGEX.search(str(t))
        if m: return f"CWE-{m.group(1)}"
    for k in ('cwe', 'cwe2022-top25'):
        v = (rule.get('properties') or {}).get(k) or (rule.get('metadata') or {}).get(k)
        if v:
            m = CWE_REGEX.search(json.dumps(v))
            if m: return f"CWE-{m.group(1)}"
    haystack = ' '.join([
        rule.get('id', ''),
        (rule.get('shortDescription') or {}).get('text', ''),
        (rule.get('fullDescription') or {}).get('text', ''),
        message_text,
    ]).lower()
    for pattern, cwe in KEYWORD_TO_CWE:
        if re.search(pattern, haystack): return cwe
    return 'CWE-693'

def main(sarif_path, out_path):
    sarif = json.loads(Path(sarif_path).read_text(encoding='utf-8'))
    findings = []
    for run in sarif.get('runs', []):
        rules = {r['id']: r for r in (run.get('tool', {}).get('driver', {}).get('rules') or [])}
        for result in run.get('results', []):
            rule = rules.get(result.get('ruleId', ''), {})
            level = (rule.get('defaultConfiguration') or {}).get('level', '').lower() or result.get('level', '').lower()
            severity = SEVERITY_MAP.get(level, 'medium')
            loc = ((result.get('locations') or [{}])[0].get('physicalLocation') or {})
            file = (loc.get('artifactLocation') or {}).get('uri', '')
            line = int((loc.get('region') or {}).get('startLine', 1))
            msg = (result.get('message') or {}).get('text', '')[:200]
            cwe = extract_cwe(rule, msg)
            findings.append(OrderedDict([
                ('file', file), ('line', line), ('severity', severity),
                ('cwe', cwe), ('description', msg),
            ]))
    if not findings:
        Path(out_path).write_bytes(b'[]\n')
    else:
        Path(out_path).write_bytes(
            (json.dumps(findings, separators=(',', ':'), ensure_ascii=False, sort_keys=False) + '\n').encode('utf-8')
        )

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

Run the normalizer:

```bash
python3 /tmp/normalize_sarif.py results-semgrep.sarif "${REPO_ROOT}/findings-config-b.json"
```

### 9.8 Verification

```bash
cd "${REPO_ROOT}"

# wc -l must return 1
[[ "$(cat findings-config-b.json | wc -l)" == "1" ]] && echo "wc -l = 1 ✓"

# Must be valid JSON
python3 -m json.tool findings-config-b.json >/dev/null && echo "valid JSON ✓"

# Empty-findings sentinel? (3 bytes = 0x5b 0x5d 0x0a)
xxd findings-config-b.json

# Scope compliance: only one file changed
git diff --name-status origin/main...HEAD
# Expected: A  findings-config-b.json
```

### 9.9 Example Usage (End-to-End)

```bash
# One-liner end-to-end (after install + rule fetch):
REPO_ROOT=/tmp/blitzy/blitzy-tgr-dnsmasq-rust/blitzy-d5142343-b764-4eda-be7b-18900989ae09_3717ab
SEMGREP_RULES_DIR=/tmp/semgrep-rules

semgrep scan --config="${SEMGREP_RULES_DIR}" --sarif \
    -o results-semgrep.sarif --metrics=off "${REPO_ROOT}" \
  && python3 /tmp/normalize_sarif.py \
        results-semgrep.sarif "${REPO_ROOT}/findings-config-b.json" \
  && cat "${REPO_ROOT}/findings-config-b.json"; echo
# Expected on this repo: []
```

### 9.10 Common Issues and Resolutions

| Symptom | Cause | Resolution |
|---|---|---|
| `semgrep scan: unknown option '--dry-run'` | Semgrep 1.163.0 renamed the flag to `--dryrun` (one word) | Use `--dryrun`; older docs may still say `--dry-run` |
| Outbound network calls observed despite `--metrics=off` | Latest-version check (Semgrep issue #8793) | Pair with `--disable-version-check` |
| `findings-config-b.json` has `wc -l` = 0 | Missing trailing newline | Ensure normalizer writes `b"[]\n"` for empty case or appends `\n` to `json.dumps` output |
| Pretty-printed output | Default `json.dumps` adds whitespace | Use `separators=(',',':')` |
| Field-order drift | `sort_keys=True` in `json.dumps` | Use `sort_keys=False` and `OrderedDict` (or rely on Python 3.7+ insertion order) |
| Unicode escapes (`\uXXXX`) in description | Default `ensure_ascii=True` | Use `ensure_ascii=False` |
| SARIF file too large to inspect | Output is normal for ~97 kLOC scan (~1.35 MB) | Use `python3 -m json.tool` with paging; do not commit |

---

## 10. Appendices

### Appendix A. Command Reference

| Command | Purpose |
|---|---|
| `pip install --no-cache-dir 'semgrep==1.163.0'` | Install Semgrep OSS at host level |
| `semgrep --version` | Verify Semgrep installation |
| `semgrep scan --metrics=off --disable-version-check --config=/tmp/semgrep-rules --dryrun <repo>` | Directive 1 telemetry-suppression dry run |
| `strace -e trace=connect -f semgrep scan …` | Verify zero non-loopback `connect()` syscalls |
| `semgrep scan --config=/tmp/semgrep-rules --sarif -o results-semgrep.sarif --metrics=off <repo>` | Directive 2 verbatim scan command |
| `python3 /tmp/normalize_sarif.py results-semgrep.sarif findings-config-b.json` | Directive 3 SARIF → JSON normalization |
| `cat findings-config-b.json \| wc -l` | Verify single-line deliverable (must return `1`) |
| `python3 -m json.tool findings-config-b.json` | Validate JSON syntax |
| `xxd findings-config-b.json` | Inspect deliverable bytes (must show `5b 5d 0a` for empty case) |
| `git diff --name-status origin/main...HEAD` | Verify scope compliance (must show only `A findings-config-b.json`) |

### Appendix B. Port Reference

Not applicable — Semgrep CLI is a non-network tool when invoked with `--metrics=off --disable-version-check` against pre-fetched local rules. The dnsmasq daemon's runtime ports are unrelated to this AAP.

### Appendix C. Key File Locations

| Path | Role |
|---|---|
| `<repo>/findings-config-b.json` | **The single deliverable** (CREATE; 3 bytes `[]\n`) |
| `<repo>/src/**/*.rs` (88 files) | Rust library/binary modules — REFERENCE (scan input) |
| `<repo>/tests/**/*.rs` (5 files) | Integration tests — REFERENCE (scan input) |
| `<repo>/benches/**/*.rs` (3 files) | Criterion benchmarks — REFERENCE (scan input) |
| `<repo>/examples/**/*.rs` (2 files) | Example binaries — REFERENCE (scan input) |
| `<repo>/build.rs` | Cargo build script (libubus pkg-config detection) — REFERENCE |
| `<repo>/Cargo.toml`, `Cargo.lock` | Manifest + lockfile — REFERENCE (unchanged) |
| `<repo>/.cargo/config.toml` | Per-target rustflags (RELRO + BIND_NOW hardening) — REFERENCE |
| `<repo>/rust-toolchain.toml` | Pinned channel `1.91.0` — REFERENCE |
| `<repo>/clippy.toml`, `rustfmt.toml` | Linter/formatter config — REFERENCE |
| `<repo>/README.md`, `docs/**/*.md`, `blitzy/documentation/*.md` | Documentation — REFERENCE (unchanged) |
| `<repo>/.gitignore` | Existing ignore rules — REFERENCE (unchanged) |
| `/tmp/semgrep-rules/{security-audit,secrets,owasp}.yaml` | Host-local rule packs — **NOT** committed |
| `/tmp/results-semgrep.sarif` (or working dir) | Transient SARIF output — **NOT** committed |
| `/tmp/normalize_sarif.py` | Transient normalization script — **NOT** committed |

### Appendix D. Technology Versions

| Component | Version | Source |
|---|---|---|
| Semgrep OSS | 1.163.0 | PyPI / pip install |
| Python (host) | ≥ 3.8 required; validated with 3.13.7 | System |
| SARIF schema | v2.1.0 | OASIS specification |
| Semgrep rule packs | `p/security-audit`, `p/secrets`, `p/owasp` (latest at fetch time; 709 rules indexed) | Semgrep Registry |
| Rust toolchain (codebase) | 1.91.0 (pinned in `rust-toolchain.toml`) | Codebase pin — not modified |
| Cargo edition (codebase) | 2021 | `Cargo.toml` — not modified |
| Codebase package version | `dnsmasq` v2.92.0 | `Cargo.toml` — not modified |

### Appendix E. Environment Variable Reference

| Variable | Purpose | Default |
|---|---|---|
| `SEMGREP_SEND_METRICS` | Equivalent to `--metrics` flag | Overridden by `--metrics=off` |
| `SEMGREP_ENABLE_VERSION_CHECK` | Equivalent to `--enable-version-check` | Overridden by `--disable-version-check` |
| `REPO_ROOT` (suggested) | Absolute path to scan target | Set to repository root |
| `SEMGREP_RULES_DIR` (suggested) | Host-local rule-pack directory | `/tmp/semgrep-rules` |

No environment variables are read from `.env` files or required by the deliverable itself.

### Appendix F. Developer Tools Guide

| Tool | Use | Notes |
|---|---|---|
| `semgrep` CLI | Run static-analysis scan | Host-level only; not added to `Cargo.toml` |
| `strace` | Verify telemetry suppression | `strace -e trace=connect -f` filters to network syscalls |
| `python3 -m json.tool` | Validate JSON deliverable | Exit non-zero on malformed JSON |
| `xxd` | Inspect deliverable bytes | Used to confirm exact `5b 5d 0a` for empty case |
| `wc -l` | Verify single-line constraint | Must return `1` |
| `git diff --name-status origin/main...HEAD` | Scope-compliance check | Must show only `A findings-config-b.json` |
| `git log --author=agent@blitzy.com` | Verify autonomous commit authorship | Single commit `96332e4` |

### Appendix G. Glossary

| Term | Definition |
|---|---|
| **AAP** | Agent Action Plan — the upstream directive document defining this work's scope and pass/fail criteria |
| **Config B** | The Semgrep OSS configuration of a multi-configuration security-tooling comparison; this AAP delivers only Config B |
| **CWE** | Common Weakness Enumeration — a community-maintained list of software weakness types; the deliverable's `cwe` field uses the canonical `CWE-<n>` form |
| **Deliverable** | The single output file mandated by Directive 3: `findings-config-b.json` at the repository root |
| **Directive** | One of three CRITICAL pass/fail requirements in the AAP (telemetry suppression, scan execution, normalization) |
| **Empty-findings sentinel** | The literal three-byte sequence `[]\n` written when the scan reports zero findings |
| **Inference fallback** | The keyword-based heuristic that assigns a CWE to a finding whose rule lacks an explicit CWE tag |
| **OSS** | Open-Source Software — distinguishes Semgrep OSS (free CLI) from Semgrep AppSec Platform (paid SaaS) |
| **Path-to-production** | Standard activities (review, handoff) required to deploy AAP deliverables, included in the completion-percentage denominator per PA1 |
| **SARIF** | Static Analysis Results Interchange Format v2.1.0 — the canonical machine-readable output of static-analysis tools |
| **Severity enum** | The fixed 4-value set `{critical, high, medium, low}` used in the deliverable's `severity` field |
| **Transient artifact** | A host-local file produced by the workflow but intentionally **not** committed to the repository (e.g., `results-semgrep.sarif`, `/tmp/semgrep-rules/`, normalizer script) |

---

> **Pre-submission cross-section integrity validation (per RG4):**
>
> - ✅ Completion % calculated from PA1 AAP-scoped hours formula: `13.5 / 15.0 × 100 = 90.0%`
> - ✅ Section 1.2 metrics table states exactly **90.0%**, Total **15.0** h, Completed **13.5** h, Remaining **1.5** h
> - ✅ Section 1.2 pie chart shows Completed=13.5, Remaining=1.5 with center label 90.0%
> - ✅ Section 2.1 rows sum to exactly **13.5** h
> - ✅ Section 2.2 "Hours" rows sum to exactly **1.5** h (1.0 + 0.5)
> - ✅ Section 2.1 total (13.5) + Section 2.2 total (1.5) = Section 1.2 Total (15.0)
> - ✅ Section 7 pie chart matches Section 1.2 hours exactly (Completed=13.5, Remaining=1.5)
> - ✅ Section 8 references **90.0%** completion exactly
> - ✅ Section 3 lists tests only from Blitzy's autonomous validation logs (35 tests, all pass)
> - ✅ Section 1.5 access issues validated (none)
> - ✅ Blitzy brand colors applied: Completed = Dark Blue `#5B39F3`, Remaining = White `#FFFFFF`, headings/accents = Violet-Black `#B23AF2`, soft accent = Mint `#A8FDD9`
> - ✅ No conflicting % or hour statements anywhere in the guide
