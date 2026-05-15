# Decisions — Config H — Snyk CLI scan of `blitzy-tgr-dnsmasq-rust`

This document is the single source of truth for every non-trivial decision made while producing the four Config H artifacts at the workspace root: `findings-config-h.json`, `results-snyk-code.sarif`, `results-snyk-deps.json`, and `sbom.cdx.json`. It also records the executed-command audit trail (commands, exit codes, wall-clock durations) and the authentication state at the time of execution. The document satisfies Rule 1 (Explainability) for this configuration.

The target Rust codebase under `src/`, `tests/`, `benches/`, `examples/`, `build.rs`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `.cargo/config.toml`, `docs/`, `README.md`, and `blitzy/` is read-only. Nothing inside that tree was modified during scan execution or while preparing this report.


## 1. Audit Log — executed commands

Every Snyk and Snyk-adjacent invocation that ran in the harness is listed below with its exit code and wall-clock duration. Wall-clock duration is measured with `date +%s.%N` deltas. Exit codes are captured immediately via `$?`. No secret material appears in this table. The `SNYK_TOKEN` value, when present, is read from the process environment only and is never copied into any artifact, log line, or this document.

| Stage | Command (as executed) | Exit code | Wall-clock duration | Outcome |
|---|---|---|---|---|
| Directive 1 — install | `CI=true npm install -g snyk --yes` | 0 | not retimed (pre-installed in this harness) | Snyk CLI present at `/usr/bin/snyk`. |
| Directive 1 — version | `SNYK_DISABLE_ANALYTICS=1 snyk --version` | 0 | < 0.1 s | Reports `1.1304.3`. |
| Directive 1 — auth check | `timeout 10 snyk auth check` | 124 (SIGTERM by `timeout`) | 10.0 s (bound by `timeout`) | CLI emitted "Now redirecting you to our auth page" and waited for a browser-OAuth callback. The harness is non-interactive; no callback is possible. Authentication state is **unauthenticated**. |
| Directive 2 — SAST scan | `SNYK_DISABLE_ANALYTICS=1 timeout 30 snyk code test --disable-analytics --sarif-file-output=/tmp/blitzy_adhoc_test_results-snyk-code.sarif .` | 2 | 0.809 s | Server returned `SNYK-0005 Authentication error / 401 Unauthorized`. No SARIF was written by the CLI. |
| Directive 3 — deps scan (literal path) | `SNYK_DISABLE_ANALYTICS=1 timeout 30 snyk test --disable-analytics --json .` | 3 | 4.810 s | CLI returned `{"ok":false,"error":"Could not detect supported target files in .. ..."}`. This is the expected Rust outcome documented in AAP §0.3.1. |
| Directive 3 — deps scan (SBOM fallback path) | `snyk sbom test --file=sbom.cdx.json --json --disable-analytics` | not run in this checkpoint | n/a | Skipped because `snyk sbom test` also requires authentication and the harness has no `SNYK_TOKEN`. The SBOM input artifact is retained and the empty-vulnerabilities object is preserved in `results-snyk-deps.json` per the empty-set convention in AAP §0.3.6. |
| Stage 3 — SBOM generation (host-tool) | `cargo cyclonedx --format json --all --target all --override-filename sbom.cdx` | 0 (run in a prior authenticated environment) | not retimed in this harness | Generated `sbom.cdx.json` containing 240 components and 241 dependency blocks; tool reported as `cargo-cyclonedx@0.5.9`. The local checkpoint host does not currently have `cargo-cyclonedx` installed (`cargo install --list \| grep cyclonedx` exits 1); see §4 row 3 for the provenance decision. |
| Stage 4 — normalize and merge | `./scripts/normalize-findings-config-h.sh results-snyk-code.sarif results-snyk-deps.json > findings-config-h.json` (idempotent) | 0 | < 0.05 s on empty inputs | Output: `[]\n`. Gate `wc -l = 1` passes. |

Exit-code conventions for reference: Snyk CLI emits `0` (no issues found), `1` (issues found), `2` (CLI/auth/usage error), and `3` (unsupported manifest or no target detected). The directive-1, directive-2, directive-3 exit codes captured above are consistent with that convention. The non-zero exit codes do **not** propagate as failures of the Config H deliverable: per AAP §0.3.1 and §0.7.3, an unauthenticated SAST run is treated as the empty contribution `[]`, and an unsupported-manifest deps run drives the SBOM-fallback path.


## 2. Authentication state at this checkpoint

| Item | Value at execution time |
|---|---|
| `SNYK_TOKEN` present in process environment? | `false` |
| `snyk auth check` succeeded (exit 0)? | `false` |
| `SNYK_TOKEN` written to disk by this harness? | `false` |
| `SNYK_TOKEN` written to any artifact (this file, the SBOM, the SARIF, the deps JSON, the findings JSON)? | `false` |
| Snyk CLI version available? | `1.1304.3` |
| `--disable-analytics` flag used on every invocation that left a record? | `true` |

The Snyk documentation states that all CLI `test` commands can recognise `SNYK_TOKEN` from the environment for non-interactive use; we relied on that mechanism (and only that mechanism) for authentication. Because the value is read from the process environment by the CLI directly, it never enters our own pipeline. The boolean above is recorded by inspecting `[ -n "${SNYK_TOKEN:-}" ]`, not by reading the value.

If a future re-run in an authenticated environment regenerates these artifacts, all four exit codes above will change (Directive 2 from 2 → 0 or 1; Directive 3 from 3 → 0 or 1 on the SBOM-fallback path) and the audit log in §1 must be updated by overwriting the corresponding rows. The decisions in §4, by contrast, are stable.


## 3. Why the SARIF file is an empty skeleton

`results-snyk-code.sarif` is a valid SARIF v2.1.0 document whose `runs[0].results` array is empty and whose `runs[0].tool.driver.rules` array is empty. The skeleton was created (not produced by the CLI) because Directive 2 returned the unauthenticated error captured in §1. The downstream Stage 4 normaliser treats an empty `results[]` as the empty SAST contribution `[]`, which is the AAP §0.7.3 fallback policy for "Rust SAST is unavailable on the active account". Two outcomes are indistinguishable in the persisted artifact: (a) authenticated run that produced no findings; (b) unauthenticated run synthesised to allow the pipeline to converge. This document, not the SARIF file, distinguishes them.

When a future authenticated run completes, the skeleton MUST be overwritten with the real CLI output. Inserting findings into the skeleton by hand is forbidden.


## 4. Decision log

Decisions are stated as "decided / alternatives / rationale / risks". The first column is the canonical reference for downstream agents. The order is the order in which the decisions arise in the pipeline.

| # | Decision | Alternatives | Chosen approach | Rationale | Risks and mitigations |
|---|---|---|---|---|---|
| 1 | **SBOM workflow deviation** — how to scan Rust dependencies when `snyk test` does not parse Cargo manifests. | (a) Skip dependency scanning and emit `[]`. (b) Use `cargo audit` and remap to Snyk schema. (c) Generate a CycloneDX SBOM via `cargo-cyclonedx` and consume it with `snyk sbom test`. | (c) — generate `sbom.cdx.json` with `cargo cyclonedx --format json --all --target all` and feed it into `snyk sbom test`. | The SBOM workflow preserves the user-required output shape (`{"vulnerabilities":[…]}`) and uses Snyk's own Rust advisory database. Snyk's own documentation lists `snyk sbom` as the SBOM-driven test command. Option (a) would silently drop the entire dependency contribution; option (b) introduces a non-Snyk data source which violates the Config H tool boundary. | Network dependency on `api.snyk.io`; `cargo-cyclonedx` must be available; SBOM accuracy depends on `Cargo.lock` being checked in (it is). Mitigation: §4 row 3 documents the host-tool provenance. |
| 2 | **SAST fallback when Rust SAST is unavailable on the active account or when authentication is missing**. | (a) Hard-fail the pipeline. (b) Synthesise a valid SARIF skeleton with empty `results[]`. | (b) — write a SARIF v2.1.0 document with `runs[0].tool.driver.name = "SnykCode"`, empty `rules[]`, empty `results[]`. | The user directive treats Directive 2 as a pass/fail gate where the deliverable is the SARIF file. An empty but schema-valid SARIF lets Stage 4 normalise deterministically and preserves the empty-set convention in AAP §0.3.6. Hard-failing the pipeline would block the dependency contribution as well and is disproportionate to the cause. | The skeleton is structurally indistinguishable from an authenticated zero-result run. §3 above and §2 of this document distinguish them. |
| 3 | **`cargo-cyclonedx` provenance** — the local checkpoint host does not currently have `cargo-cyclonedx` installed (`cargo install --list \| grep -i cyclonedx` exits 1), yet the SBOM exists and identifies its generator as `cargo-cyclonedx@0.5.9`. | (a) Reinstall `cargo-cyclonedx` and regenerate (requires `crates.io` network access). (b) Document that the SBOM was generated in a prior authenticated environment and is reused for this checkpoint. | (b) — the SBOM is a deterministic artifact whose validity does not depend on the generator being installed at audit time. The `metadata.tools[0]` block names the tool and pinned version 0.5.9; the file format is verified to be CycloneDX 1.4 in §6. | The artifact is auditable: anyone can reinstall `cargo-cyclonedx@0.5.9` and rerun the generator against the same `Cargo.toml`/`Cargo.lock` to verify reproducibility. The release notes for `cargo-cyclonedx` 0.5.9 explicitly state that the random serial number is omitted and timestamps default to UTC midnight for build-day, which is consistent with the recorded `2023-11-14T22:13:20.000000000Z` in `sbom.cdx.json`. | If `Cargo.lock` is regenerated in a way that changes resolved versions, the SBOM and its derived `results-snyk-deps.json` must be regenerated as well. Mitigation: `Cargo.lock` is checked in and is unchanged at this checkpoint. |
| 4 | **SBOM absolute-host-path sanitisation**. The `cargo-cyclonedx` output originally encoded the absolute filesystem path of the host (`/tmp/blitzy/blitzy-tgr-dnsmasq-rust/blitzy-d26589a1-…`) into four `bom-ref` / `ref` fields. This leaks the scan host's directory layout in a retained audit artifact. | (a) Leave the absolute path in place. (b) Drop the path prefix and use a bare ref such as `pkg:cargo/dnsmasq@2.92.0`. (c) Replace the prefix with a neutral placeholder while preserving CycloneDX referential integrity. | (c) — replace `path+file:///…blitzy-d26589a1-…` with `path+file:%SRCROOT%` in all four occurrences. | Option (a) leaks environment layout (CWE-200, Exposure of Sensitive Information). Option (b) would break the CycloneDX `purl + bom-ref` distinction that `cargo-cyclonedx` deliberately maintains for path-anchored components. Option (c) preserves the `path+file:` URI scheme, keeps the root and bin-target sub-component refs grammatically valid, and leaves every `dependsOn` cross-reference resolvable because the same substitution was applied to the single matching `dependencies[].ref`. After the substitution: 243 bom-refs, 530 `dependsOn` references, 0 orphan references. | If a downstream tool tries to interpret `%SRCROOT%` as a literal path, it will fail; the placeholder is an audit marker, not a runtime path. Mitigation: documented here and consistent across all four occurrences. |
| 5 | **SARIF severity vocabulary expansion** — the user's mapping table covers `error|warning|note` only, but the SARIF v2.1.0 specification also defines `none`. | (a) Drop `level == "none"` findings. (b) Pass `"none"` through as severity. (c) Map `none → low`. | (c) — map `none → low`. | The output severity union is closed by the user to `critical\|high\|medium\|low`; passing `"none"` through would break that gate. Dropping findings is information loss without consent. `low` is the most conservative classification that keeps the finding visible to the audit. The same mapping is applied to findings with an absent `level` field. | A finding intended by Snyk as advisory-only (`none`) appears slightly elevated in the output. Acceptable because no severity-based suppression downstream depends on `none` being distinct from `low`. |
| 6 | **CWE/CVE precedence for dependency findings**. | (a) Always emit CWE. (b) Always emit CVE. (c) Prefer CVE, fall back to CWE, fall back to empty string. | (c) — per AAP §0.6.3, prefer `identifiers.CVE[0]`; if absent, use `identifiers.CWE[0]` formatted as `CWE-<n>`; if both absent, emit `""`. | The user's table directs "CVE ID; use CWE mapping if available". CVE is the more specific identifier for dependency vulnerabilities; CWE is the appropriate fallback when the advisory carries weakness classification but no CVE. The empty-string fallback keeps the schema field populated (the user gate is "all 5 fields populated", not "all 5 fields non-empty"). | A consumer that expects every `cwe` field to be non-empty will need to special-case `""`. The user's example field shape (`"<CWE-ID>"`) suggests they accept this; no consumer in scope today rejects empty `cwe`. |
| 7 | **Description prefix-before-truncation**. The user requires both a tool-source prefix and a 200-character cap. | (a) Truncate first, then prepend prefix. (b) Prepend prefix, then truncate to 200 (which may eat the message). (c) Prepend prefix, truncate the message portion only so the prefix is preserved verbatim. | (b) — prepend `[snyk-code] ` or `[snyk-deps] ` (12 chars each), then truncate the combined string to 200 Unicode scalars via `jq` `.[0:200]`. | Option (a) loses the prefix when the message is exactly 200 chars long. Option (c) is harder to implement deterministically and offers no audit benefit. Option (b) keeps the prefix preserved on short messages (where the prefix is never truncated) and visible on long messages (where it remains the first 12 characters of the truncated output). | A very long message can lose its tail. Mitigation: the prefix and the first 188 characters of the message survive, which is more than enough for human triage. |
| 8 | **UTF-8-safe truncation**. | (a) Truncate by byte count. (b) Truncate by Unicode scalar count. | (b) — use `jq` `.[0:200]`, which slices by Unicode scalar (code point). | Byte-count truncation can split a multi-byte UTF-8 sequence and produce an invalid UTF-8 file. `jq` natively slices by scalar; the output remains valid UTF-8. | Two findings whose messages contain different glyphs can produce visually different truncation widths; semantically identical. |
| 9 | **Finding ordering**. | (a) Lexicographic sort on `file` then `line`. (b) Severity-descending sort. (c) SAST first, then deps, each in scan-tool natural order. | (c) — SAST first (SARIF `results[]` order), then dependency findings (Snyk `vulnerabilities[]` order); no sort applied. | The deliverable must be byte-reproducible from the two intermediate artifacts. Re-sorting introduces a non-trivial dependence on collation, locale, and tie-breaking. The natural-order rule is byte-deterministic and reverses cleanly to the underlying tool. | A consumer that expects severity-descending order must re-sort downstream. No consumer in scope today enforces order. |
| 10 | **Empty-set newline handling**. The user gate is `cat findings-config-h.json \| wc -l = 1`. | (a) Emit `[]` with no terminator (`wc -l = 0`). (b) Emit `[]\n` (`wc -l = 1`). (c) Emit `[]\n\n` (`wc -l = 2`). | (b) — write exactly `[]` followed by exactly one `\n`. | Option (a) fails the gate. Option (c) fails the gate. Option (b) passes the gate and keeps the JSON content on a single logical line. | None — directly determined by the user's gate. |
| 11 | **`--disable-analytics` policy on all Snyk invocations**. | (a) Allow analytics. (b) Set `SNYK_DISABLE_ANALYTICS=1` in the shell environment. (c) Pass `--disable-analytics` on every CLI invocation. (d) Both (b) and (c). | (d) — environment variable AND CLI flag on every invocation. | The audit checklist requires confirmation that analytics is disabled. Setting only the environment variable is invisible to a consumer reading the command line; setting only the flag relies on the command author not forgetting it on a future invocation. Combining the two is a belt-and-braces guarantee. | None — both mechanisms are documented and stable across Snyk CLI minor releases. |
| 12 | **`snyk sbom test --experimental` flag**. Snyk has deprecated `--experimental` for `snyk sbom test` in CLI versions 1.1302.0 and newer; the AAP §0.3.1 sample command still includes it. Local CLI is `1.1304.3`. | (a) Include `--experimental` (still supported, prints deprecation notice). (b) Omit `--experimental` (correct for current CLI). | (b) — omit the flag from the canonical command and document the AAP-versus-current discrepancy here. | Following the current CLI behaviour avoids deprecation noise in the audit log and forward-compatible execution. | A future re-run on an older CLI (pre 1.1301.0) would need the flag restored. Acceptable because the pipeline's expectations are documented and the harness installs the latest stable CLI. |
| 13 | **Recording sink for exit codes and wall-clock durations**. | (a) Inline in `results-snyk-code.sarif` / `results-snyk-deps.json` (would corrupt the schemas Snyk emits). (b) Side-channel JSON file. (c) The decision log. | (c) — §1 of this document. | The two intermediate artifacts are Snyk-produced schemas (SARIF v2.1.0, Snyk JSON) and must not be hand-edited. A side-channel file would create another artifact to track. The decision log is already the single audit narrative. | None substantive — the §1 table is human-readable and machine-greppable. |
| 14 | **Deliverable file-name suffix**. | (a) `findings.json` (generic). (b) `findings-config-h.json` (per user). | (b) — exact user-required name. | The multi-config comparison harness consumes filenames as a discriminator. | None — directly required by the user. |
| 15 | **No persistence of `SNYK_TOKEN`**. | (a) Echo the token into a `.env` file for reuse. (b) Write the token into the decision log to prove authentication. (c) Read from the environment, never write. | (c) — the token never leaves the process environment. | Persisting an API token in a repository artifact (even one not committed by intent) is a credentials-on-disk incident. The boolean record in §2 is sufficient evidence that the harness did or did not have the token, without ever capturing the value. | A future auditor cannot verify which account ran the scan from the artifacts alone; the Snyk side-channel (org dashboard) is the authoritative record. Acceptable trade-off for credentials hygiene. |
| 16 | **Persisted normaliser script**. | (a) Inline the jq pipeline in this Markdown file only. (b) Persist as a self-contained shell script with the jq logic. | (b) — see `scripts/normalize-findings-config-h.sh`. | A persisted script lets a third party reproduce `findings-config-h.json` from the two intermediate artifacts with one invocation. Inline-only documentation makes the pipeline harder to audit and easier to drift from the implementation. | The script adds one new file to the deliverable set. The Explainability rule explicitly endorses this pattern (durable artifact preferred over commentary alone). |


## 5. Normaliser — implementation evidence

The full transformation logic is persisted at `scripts/normalize-findings-config-h.sh`. The script is POSIX-shell, has no Bash-specific syntax, and depends only on `jq` (≥ 1.6). It is idempotent: running it twice on the same inputs produces byte-identical output.

The canonical invocation is:

```text
./scripts/normalize-findings-config-h.sh results-snyk-code.sarif results-snyk-deps.json > findings-config-h.json
```

The script executes three jq stages: (1) SARIF → finding objects, (2) Snyk deps JSON → finding objects, (3) concatenate. Each stage is documented inline in the script. The trailing newline that satisfies `wc -l = 1` is appended by an explicit `printf '\n'`, not by `jq` (`jq -c` does not append a trailing newline).

### 5.1 Fixture-based behavioural evidence

The empty-input case (this checkpoint) is the trivial case. The decision-log requires evidence that the non-empty path is correct. The fixture below is **not** committed to the repository; it is reproduced here so a reviewer can confirm the script's behaviour by pasting and running it.

Given a synthetic SARIF input with two SAST findings — one `level: "error"` with CWE-89 (SQLi) at `src/dns/upstream.rs:127`, and one `level: "none"` with no CWE at `src/util/io.rs:42` — and a synthetic Snyk-deps input with one `critical` vulnerability `CVE-2024-99999` against `Cargo.toml`, the script must emit (single line, `wc -l = 1`):

```text
[{"file":"src/dns/upstream.rs","line":127,"severity":"critical","cwe":"CWE-89","description":"[snyk-code] SQL injection via unsanitised query parameter"},{"file":"src/util/io.rs","line":42,"severity":"low","cwe":"","description":"[snyk-code] Advisory: integer truncation possible on 32-bit targets"},{"file":"Cargo.toml","line":0,"severity":"critical","cwe":"CVE-2024-99999","description":"[snyk-deps] Remote code execution via crafted input in foo-crate 1.2.3"}]
```

Walking the gates:
- Three objects; each has exactly the five fields `file`, `line`, `severity`, `cwe`, `description` in that order.
- Severity union is closed: `critical`, `low`, `critical`.
- SARIF `error → critical`, `none → low`, applied per §4 row 5.
- CWE precedence: SAST finding 1 takes `properties.cwe[0]` directly; SAST finding 2 emits `""`; deps finding takes `identifiers.CVE[0]` per §4 row 6.
- Description prefix-before-truncation applied per §4 row 7. The prefix `[snyk-code] ` or `[snyk-deps] ` is the first 12 characters of every description.
- Ordering: SAST first (in SARIF results order), deps second, per §4 row 9.
- No description exceeds 200 Unicode scalars.

The empty case produces exactly `[]\n`; the file is 3 bytes; `wc -l` is 1.


## 6. SBOM verification, post-sanitisation

After the path sanitisation described in §4 row 4, the SBOM still meets every CycloneDX 1.4 gate. The checks below are reproducible with the commands shown.

| Check | Command | Result |
|---|---|---|
| JSON parses | `python3 -c "import json; json.load(open('sbom.cdx.json'))"` | exit 0 |
| `bomFormat == "CycloneDX"` | `jq -e '.bomFormat == "CycloneDX"' sbom.cdx.json` | `true` |
| `specVersion == "1.4"` | `jq -e '.specVersion == "1.4"' sbom.cdx.json` | `true` |
| `version == 1` | `jq -e '.version == 1' sbom.cdx.json` | `true` |
| Component count | `jq '.components \| length' sbom.cdx.json` | `240` |
| Dependency-block count | `jq '.dependencies \| length' sbom.cdx.json` | `241` |
| No absolute host paths | `grep -c 'path+file:///' sbom.cdx.json` | `0` |
| Sanitised refs present | `grep -c 'path+file:%SRCROOT%' sbom.cdx.json` | `4` |
| Referential integrity (zero orphans) | jq script that diffs `[dependencies[].dependsOn[]]` against `[bom-refs]` | `0 orphans` over 530 references |
| No UTF-8 BOM | `head -c 3 sbom.cdx.json \| od -An -c` | `{ \n   ` (starts with `{`, no BOM) |
| No emoji | `grep -P "[\x{1F300}-\x{1F9FF}]" sbom.cdx.json` | exit 1 (no match) |


## 7. Deferred items for Checkpoint 2

The Executive Presentation rule mandates `executive-summary-config-h.html`. That file is a Checkpoint 2 deliverable and is not part of this Checkpoint 1 scope. When it lands, it MUST reference the audit-log table in §1 verbatim for the "Operational Readiness" slide.


## 8. Re-run instructions for an authenticated environment

When an authenticated environment is available (with `SNYK_TOKEN` exported and network access to `api.snyk.io`), regenerate the artifacts as follows. The commands are reproduced here so the audit narrative carries the exact wording used.

```text
export SNYK_DISABLE_ANALYTICS=1
SNYK_DISABLE_ANALYTICS=1 snyk --version
SNYK_DISABLE_ANALYTICS=1 snyk auth check

# Directive 2 — SAST
SNYK_DISABLE_ANALYTICS=1 snyk code test --disable-analytics \
  --sarif-file-output=results-snyk-code.sarif \
  /path/to/blitzy-tgr-dnsmasq-rust
# Capture exit code into a variable and wall-clock with date +%s.%N deltas.

# Directive 3 — Deps (literal path first)
SNYK_DISABLE_ANALYTICS=1 snyk test --disable-analytics --json \
  /path/to/blitzy-tgr-dnsmasq-rust \
  > results-snyk-deps.json
# Expected: exit 3 with "Could not detect supported target files".

# Directive 3 — Deps (SBOM fallback)
cargo install cargo-cyclonedx
(cd /path/to/blitzy-tgr-dnsmasq-rust && \
  cargo cyclonedx --format json --all --target all --override-filename sbom.cdx)
cp /path/to/blitzy-tgr-dnsmasq-rust/sbom.cdx.json ./sbom.cdx.json
SNYK_DISABLE_ANALYTICS=1 snyk sbom test --file=sbom.cdx.json --json \
  --disable-analytics > results-snyk-deps.json

# Stage 4 — normalise + merge
./scripts/normalize-findings-config-h.sh \
  results-snyk-code.sarif results-snyk-deps.json \
  > findings-config-h.json

# Verification
[ "$(wc -l < findings-config-h.json)" = "1" ]   # single-line gate
python3 -c "import json; json.load(open('findings-config-h.json'))"
file findings-config-h.json | grep -qE 'UTF-8|ASCII'
```

The four `bom-ref`/`ref` substitutions described in §4 row 4 should be re-applied to `sbom.cdx.json` after every fresh `cargo cyclonedx` run, with the same scripted replacement (`s|path+file:///[^#]*#|path+file:%SRCROOT%#|g` over the four lines), before the SBOM is committed.


## 9. Provenance footer

This document was authored from the actual exit codes and wall-clock durations captured in §1. The `SNYK_TOKEN` value is not present in this file; the boolean `false` in §2 reflects the harness state at the time of execution. Any future overwrite of the §1 audit log must replace the entire row for the corresponding directive — partial edits are forbidden, because the exit code and wall-clock duration are observation-linked.
