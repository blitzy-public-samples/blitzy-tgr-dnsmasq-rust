# Config H — Snyk CLI — Decision Log

This document satisfies the Explainability rule for Config H. It records every non-trivial
implementation decision taken while producing `findings-config-h.json`, including the
alternatives considered, the choice made, the rationale, and the residual risk. It is the
single source of truth for "why"; rationale is not duplicated inside the normalizer script,
the executive summary, or the deliverable itself.

The scan target is `blitzy-tgr-dnsmasq-rust`, a Rust 2021 reimplementation of dnsmasq
v2.92.0 pinned to Rust 1.91.0 via `rust-toolchain.toml`. The codebase under audit is read
only; no Rust source file, `Cargo.toml`, `Cargo.lock`, or build configuration was modified
to accommodate the scanner.

---

## Run inventory

| Stage | Command | Exit code | Wall clock | Outcome |
|---|---|---|---|---|
| Auth verification | `snyk whoami` | 0 | <1s | Returned account identifier `michael`; `SNYK_TOKEN` confirmed valid. |
| CLI version | `snyk --version` | 0 | <1s | Snyk CLI 1.1304.3. |
| Refine PR Directive 1 (literal) | `snyk test --all-projects --severity-threshold=high` from repo root | 3 | 4s | Snyk error SNYK-CLI-0008: "Could not detect supported target files." `snyk test` does not natively parse Cargo manifests. Fallback path triggered per AAP §0.3.1. |
| SBOM generation (fallback) | `cargo cyclonedx --format json --spec-version 1.5 --all --target all --override-filename sbom.cdx` | 0 | <1s | Produced `sbom.cdx.json`, 240 components, CycloneDX 1.5 JSON, every component identified by `pkg:cargo/...` purl. |
| Refine PR Directive 1 (fallback) | `snyk sbom test --file=sbom.cdx.json --severity-threshold=high --json` | 1 | 10s | Exit 1 indicates vulnerabilities found. Wrote `results-snyk-deps.json` with 4 vulnerable paths across 3 unique advisories (all high). A non-fatal "Forbidden" telemetry post appeared on stderr; it did not affect the scan output. |
| Refine PR Directive 2 | `snyk code test --sarif-file-output=results-snyk-code.sarif .` | 0 | 19s | Wrote `results-snyk-code.sarif`, valid SARIF v2.1.0, 0 results, 0 rules. SARIF coverage block reports only `.html` files as supported, consistent with Rust SAST being in Early Access tier and not enabled for the active organization. |
| Refine PR Directive 3 | Report pass/fail | — | — | See "Pass/fail report" below. |

---

## Pass/fail report (Refine PR Directive 3)

| Refine PR Directive | Command | Pass/Fail | Evidence |
|---|---|---|---|
| 1. Dependency scan with `--severity-threshold=high` | `snyk sbom test --file=sbom.cdx.json --severity-threshold=high --json > results-snyk-deps.json` (after literal `snyk test --all-projects` fallback) | **FAIL** (vulnerabilities found) | 3 unique high-severity advisories: SNYK-RUST-RAND-16073005 (Out-of-Bounds, CWE-119, rand 0.8.5); SNYK-RUST-HICKORYPROTO-16346057 (Inefficient Algorithmic Complexity, CWE-407, hickory-proto 0.25.2); SNYK-RUST-HICKORYPROTO-16346342 (Infinite loop, CWE-835, hickory-proto 0.25.2). All advisories also referenced in RustSec. Snyk CLI exit code 1. |
| 2. SAST scan | `snyk code test --sarif-file-output=results-snyk-code.sarif .` | **PASS** (no issues at the rule pack engaged for this account) | SARIF reports 0 results across 0 rules; coverage block lists `.html` as the only language with loaded rules, which means the Rust rule pack was not engaged. The empty-result outcome is recorded so the normalizer treats the SAST contribution as the empty set. Snyk CLI exit code 0. |
| 3. Report pass/fail | This table | — | See above. The combined deliverable surfaces 4 high-severity findings (the deduplicated count is 3; each finding row in `findings-config-h.json` corresponds to one `vulnerabilities[]` entry, including the duplicate dependency path for `rand`). |

---

## Decisions

| Decision | Alternatives | Chosen | Rationale | Risks |
|---|---|---|---|---|
| Use the CycloneDX SBOM fallback path for the dependency scan | (a) Honour only the literal `snyk test --all-projects` directive and emit an empty `vulnerabilities` array; (b) Use `snyk test --package-manager=cargo` (not a Snyk-supported manager in `snyk test`); (c) Vendor `cargo-audit` results into a synthesised Snyk envelope. | (b) generates no output; (c) violates the "Snyk CLI only" framing. The fallback path uses `cargo cyclonedx` and `snyk sbom test`, both first-party tools, and produces the same JSON schema Snyk's other commands emit. | The fallback path is documented by Snyk for Rust projects; `snyk sbom test` consumes the same CycloneDX format that `cargo-cyclonedx` produces and resolves dependencies through Snyk's Rust advisory database. The output schema (top-level `vulnerabilities` array) is identical, so the downstream normalizer is unchanged. | The path adds two transitive trust assumptions: the integrity of `cargo-cyclonedx` 0.5.9 and the completeness of Snyk's Rust advisory coverage. Mitigated by also referencing RustSec advisory IDs in the results. |
| Honor the Refine PR `--severity-threshold=high` flag | (a) Drop the flag and emit findings at every severity; (b) Apply the threshold during normalization rather than at the scanner. | (a) would surface low/medium noise the user explicitly excluded; (b) is technically equivalent but harder to audit because the raw `results-snyk-deps.json` would no longer be filtered. | Passing `--severity-threshold=high` to `snyk sbom test` means the intermediate artifact and the final deliverable both reflect the user's threshold without further filtering, which keeps the pipeline deterministic and the decision log honest about what Snyk reported. | Low/medium-severity findings exist in the unfiltered Snyk view but are excluded from this deliverable by design. A separate run without the flag would surface them; this is consistent with the Refine PR instruction. |
| Use CycloneDX 1.5 (not 1.3 default, not 1.6) | (a) Default CycloneDX 1.3; (b) Newest CycloneDX 1.6. | 1.3 is older than `snyk sbom test`'s minimum supported version (1.4). 1.6 is the newest spec, but `cargo-cyclonedx` 0.5.9 only writes through 1.5. | 1.5 is the highest spec version available on both sides of the pipeline and exposes the full set of fields Snyk consumes today. | A newer `cargo-cyclonedx` release may default to 1.6 and require this script to be updated. The script pins `--spec-version 1.5` explicitly so the choice is reproducible. |
| Emit `Cargo.toml` as the `file` for every dependency finding | (a) `vulnerabilities[].from[0]` (e.g., `"dnsmasq@2.92.0"`); (b) `sbom.cdx.json` (the file Snyk actually scanned); (c) the package's own name (e.g., `"rand"`). | (a) is a package identifier, not a manifest path. (b) is an intermediate artifact and not the project's dependency manifest. (c) is not a file path at all. | The AAP §0.4.1 and §0.6.3 designate `Cargo.toml` as the canonical relative manifest path for Rust dependency findings; this is what a reader would inspect to remediate. Every advisory in the deliverable originates from a dependency declared transitively or directly through `Cargo.toml`. | All four findings share the same `file` value. A multi-crate Rust workspace would require disambiguation by sub-crate manifest path; this repository is a single crate so the value is unambiguous here. |
| Map SARIF `none → low` and absent SARIF level → `low` | Drop findings with unmapped levels; treat them as `medium` to be conservative; assign a fifth severity outside the closed union. | Dropping findings loses signal. `medium` is not the most conservative interpretation in this direction; `low` preserves the finding while signaling the absence of a more severe classification. A fifth severity would break the user's closed union. | Keeps the output `severity` union closed to `critical|high|medium|low` exactly as the user's schema mandates, and never silently discards a finding. | A SARIF rule whose `level` is intentionally `none` (advisory only) appears as `low` in the deliverable rather than being filtered. Acceptable under the user's "all five fields populated" gate. |
| For dependency findings, prefer CVE over CWE in the `cwe` field | Always emit CWE; always emit CVE; emit both joined by a separator. | The user's field-mapping table is explicit: "CVE ID; use CWE mapping if available." Joining two identifiers in one slot would violate the schema. | The user directive is followed literally: CVE first, CWE as fallback. The field is named `cwe` but the schema is documented to accept either identifier class for dependency rows. | A reader unfamiliar with the user's directive may be surprised to find a CVE ID in a field named `cwe`. The README-style note in this decision log is the mitigation. In the current data set, all three unique advisories have CWE but no CVE, so the field carries CWE values exclusively. |
| Prepend `[snyk-code] ` or `[snyk-deps] ` before truncating descriptions | Append the prefix after truncation; carry the source tool in a separate field. | The user's schema has exactly five fields; adding a sixth would violate the schema. Appending after truncation can lose the prefix on long descriptions. | Prefixing before truncation guarantees the source tool is always identifiable, even when the description is cut by the 200-character bound. The 12-character `[snyk-deps] ` prefix leaves 188 characters for the message itself. | A pathological description that begins with whitespace or special characters could push the cut point earlier than necessary. Empirically the worst case in this run is 46 characters, well under the bound. |
| Truncate `description` by Unicode scalar count using `jq`'s `.[0:200]` | Byte-slice via `awk substr`; codepoint-slice via Python. | Byte slicing can split a multi-byte UTF-8 sequence and produce invalid UTF-8. Python introduces an extra runtime dependency for a one-line transformation. | `jq`'s array/string slicing operates on Unicode scalars when applied to strings, which is exactly what the schema requires. The script remains a single `jq` pipeline. | Surrogate pairs (used by no Snyk advisory observed to date) would be sliced as two scalars rather than one user-perceived character. Acceptable: the deliverable is for machine consumption. |
| SAST findings precede dependency findings; no sort applied | Sort by severity descending; sort by file path alphabetically; deduplicate by `(file, line, cwe)`. | Sorting breaks reproducibility from a fresh re-scan because Snyk's natural order is itself the canonical order. Deduplicating would hide that `rand@0.8.5` is reached through more than one path. | The output is byte-reproducible from the same `results-snyk-code.sarif` and `results-snyk-deps.json` without invoking sort. Operators can re-derive any ordering they want from this deliverable. | Two `rand@0.8.5` rows appear because Snyk reports two `from` chains for that advisory. This is the truthful representation of the dependency graph. |
| Emit `[]\n` (one newline, one line) when both arrays are empty | Emit `[]` with no trailing newline; emit an empty file; emit a JSON object `{ "findings": [] }`. | An empty file or no-newline emission fails the user's `wc -l = 1` gate. Wrapping in an object violates the schema. | Single trailing newline satisfies the gate while keeping the JSON content on one line. Same `printf '%s\n'` writer used in the populated case. | None observed. |
| Save run artifacts at workspace root | A nested `artifacts/` directory; a temp directory under `/tmp`. | A nested directory would require the user to qualify the `wc -l` command; `/tmp` would not survive the commit phase. | Workspace-root placement matches the user's verification command exactly and persists with the repository. The six artifacts (`findings-config-h.json`, `decisions-config-h.md`, `executive-summary-config-h.html`, `results-snyk-code.sarif`, `results-snyk-deps.json`, `sbom.cdx.json`) are clearly named with the `-config-h` suffix where required by the user. | The artifacts add ~300 KB to the tree. Acceptable. |
| Record auth via `SNYK_TOKEN` environment variable only | Persist to `~/.config/configstore/snyk.json`; pass `--token=` on the command line. | Persisting to disk creates a credential leak risk; passing the token inline exposes it in shell history and process listings. | The token is consumed transparently by the CLI from the environment and never written to disk by this pipeline. The setup confirmation `cat /root/.config/configstore/snyk.json = {}` is documented in the Setup Status Log. | Anyone with `/proc/<pid>/environ` access on the host could read the token while a Snyk command is running. This is the standard Snyk CLI threat model and is not a Config-H-specific risk. |
| Treat Snyk's "Forbidden" telemetry response as non-fatal | Abort the pipeline on any non-zero stderr; require a clean stderr. | Aborting on a non-fatal telemetry post would discard a complete, valid scan output. The Snyk CLI returns its actual exit code separately from telemetry attempts. | The intended exit code (1 = vulnerabilities found) is honored; the stderr message is preserved in `.blitzy-run/` for audit. The scan result on stdout is the authoritative output. | If Snyk introduces a future behavioural change where "Forbidden" indicates a missing entitlement that does affect output, this assumption would need revisiting. The decision log makes the assumption auditable. |

---

## Empty SAST result interpretation

The SAST scan returned 0 results, 0 rules, and a SARIF coverage block listing only `.html`
as a supported language. Three causes are possible:

1. **Rust rule pack not engaged for this account.** Snyk Code's Rust support is in the
   Early Access tier; the active organization (`c78a6b60-47b6-4bac-a32c-2cca9d06ad32`) may
   not have it enabled. This is the most likely cause given the coverage block's
   composition.
2. **Genuinely zero Rust findings.** With Rust rules engaged, the scanner could have run
   and found nothing in the 63 Rust files; the absence of any rule metadata in the SARIF
   makes this interpretation unlikely.
3. **CLI version mismatch.** Snyk CLI 1.1304.3 is recent; a rule-pack regression in this
   minor would not have been silently swallowed.

Per the AAP §0.7.3, the chosen response is to accept the empty SARIF as authoritative for
the SAST contribution and proceed with normalization. The dependency scan is unaffected.

---

## Verification gates (final deliverable)

| Gate | Command | Expected | Actual | Status |
|---|---|---|---|---|
| `wc -l` | `wc -l < findings-config-h.json` | `1` | `1` | PASS |
| Valid JSON | `jq . findings-config-h.json` | parses | parses | PASS |
| All five fields | `jq 'all(.[]; has("file") and has("line") and has("severity") and has("cwe") and has("description"))' findings-config-h.json` | `true` | `true` | PASS |
| Severity union closed | `jq 'all(.[]; .severity | IN("critical","high","medium","low"))' findings-config-h.json` | `true` | `true` | PASS |
| Description bound | `jq 'all(.[]; (.description | length) <= 200)' findings-config-h.json` | `true` | `true` (max observed: 46) | PASS |
| UTF-8 encoding | `file -bi findings-config-h.json` | `application/json; charset=us-ascii` or `...; charset=utf-8` | `application/json; charset=us-ascii` (a subset of UTF-8) | PASS |
| Single-line minified | byte-level inspection | one `\n` at end | one `\n` at end (offset 0x1c2) | PASS |

---

## Files emitted

| Path | Purpose | Bytes |
|---|---|---|
| `findings-config-h.json` | Primary deliverable; 4 high-severity dependency findings, single-line minified UTF-8 JSON array, five-field schema. | 451 |
| `decisions-config-h.md` | This file (Explainability rule). | — |
| `executive-summary-config-h.html` | Reveal.js leadership presentation (Executive Presentation rule). | — |
| `results-snyk-code.sarif` | SARIF v2.1.0 from Refine PR Directive 2 (`snyk code test`). | 463 |
| `results-snyk-deps.json` | JSON envelope from Refine PR Directive 1 fallback (`snyk sbom test`). | 16,784 |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM produced by `cargo cyclonedx`; consumed by `snyk sbom test`. | 282,697 |
| `scripts/normalize-findings-config-h.sh` | Deterministic SARIF + Snyk JSON to five-field schema normalizer; invoked by the harness, retained in the tree so the deliverable is reproducible from raw scanner output. | — |

No Rust source file, `Cargo.toml`, `Cargo.lock`, `build.rs`, or build configuration was
modified. The audit target is byte-identical to its pre-scan state.

---

## Reproducibility

To reproduce this deliverable from the raw scanner inputs:

`bash -c 'cargo cyclonedx --format json --spec-version 1.5 --all --target all --override-filename sbom.cdx && snyk sbom test --file=sbom.cdx.json --severity-threshold=high --json > results-snyk-deps.json; snyk code test --sarif-file-output=results-snyk-code.sarif . ; ./scripts/normalize-findings-config-h.sh results-snyk-code.sarif results-snyk-deps.json > findings-config-h.json'`

The pipeline is idempotent: running it twice on the same Cargo manifest and the same Snyk
advisory database state produces a byte-identical `findings-config-h.json`. Snyk's
advisory database is mutable, so a re-run after Snyk publishes a new advisory for a
dependency already in `Cargo.lock` will surface the new finding without changing the
pipeline.
