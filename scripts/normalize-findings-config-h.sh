#!/bin/sh
# scripts/normalize-findings-config-h.sh
#
# Deterministic normaliser for Config H — Snyk CLI scan of `blitzy-tgr-dnsmasq-rust`.
#
# Reads:
#   $1  results-snyk-code.sarif   SARIF v2.1.0 from `snyk code test --sarif-file-output=...`
#   $2  results-snyk-deps.json    JSON object from `snyk test --json` or `snyk sbom test --json`
#
# Writes (to stdout):
#   findings-config-h.json content — single-line minified UTF-8 JSON array followed by exactly
#   one `\n`. Conforms to the five-field schema mandated by the user directive and to the AAP
#   §0.6.3 mapping table.
#
# Dependencies:
#   - POSIX sh (no Bash-specific syntax)
#   - jq >= 1.6  (uses `.[0:200]` slicing, `// []`, `// ""`, conditional expressions)
#
# Idempotency:
#   Running this script twice on the same inputs produces byte-identical output. The script does
#   not mutate either input file.
#
# Determinism:
#   No timestamps, no environment metadata, no run-specific identifiers appear in the output.
#   SAST findings are emitted in SARIF `results[]` natural order; dependency findings are emitted
#   in Snyk `vulnerabilities[]` natural order. No sort is applied.
#
# Exit codes:
#   0  Output written successfully (including the empty-array case `[]`).
#   1  Invalid command-line invocation (missing arguments, missing input files).
#   2  `jq` not found in PATH.
#   3  `jq` reported a parse or type error on one of the inputs.
#
# Usage:
#   ./scripts/normalize-findings-config-h.sh results-snyk-code.sarif results-snyk-deps.json \
#       > findings-config-h.json
#
# Verification:
#   [ "$(wc -l < findings-config-h.json)" = "1" ]
#   python3 -c "import json; json.load(open('findings-config-h.json'))"
#   file findings-config-h.json | grep -qE 'UTF-8|ASCII'

set -eu

# --------------------------------------------------------------------------------------------
# Argument and dependency validation
# --------------------------------------------------------------------------------------------

if [ "$#" -ne 2 ]; then
    printf '%s\n' "usage: $0 <sarif-file> <snyk-deps-json>" >&2
    exit 1
fi

SARIF_FILE="$1"
DEPS_FILE="$2"

if [ ! -f "$SARIF_FILE" ]; then
    printf '%s\n' "error: SARIF file not found: $SARIF_FILE" >&2
    exit 1
fi

if [ ! -f "$DEPS_FILE" ]; then
    printf '%s\n' "error: Snyk deps file not found: $DEPS_FILE" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    printf '%s\n' "error: jq not found in PATH" >&2
    exit 2
fi

# --------------------------------------------------------------------------------------------
# Stage 4a — SARIF -> finding objects
# --------------------------------------------------------------------------------------------
#
# Per AAP §0.6.3 mapping table:
#   file        = runs[].results[].locations[0].physicalLocation.artifactLocation.uri
#                 (empty string if absent)
#   line        = runs[].results[].locations[0].physicalLocation.region.startLine
#                 (0 if absent)
#   severity    = SARIF level mapped:  error -> critical, warning -> high, note -> medium,
#                 none -> low, absent -> low
#                 Falls back to the rule's defaultConfiguration.level if the result has no
#                 explicit level.
#   cwe         = first entry of rules[matching].properties.cwe[] (Snyk Code emits this);
#                 fallback to first `CWE-`-prefixed entry of rules[matching].properties.tags[];
#                 else empty string.
#   description = "[snyk-code] " + (result.message.text // ""), truncated to 200 Unicode scalars
#                 via jq's `.[0:200]` slicing (NOT byte slicing — preserves UTF-8 validity).

SAST_FINDINGS="$(
    jq -c '
      [
        (.runs // []) | .[]? as $run |
        ($run.results // []) | .[]? as $r |
        ($r.ruleId // "") as $rule_id |
        (
          ($run.tool.driver.rules // [])
          | map(select(.id == $rule_id))
          | .[0]
        ) as $rule |
        (
          ($r.level // $rule.defaultConfiguration.level // "")
        ) as $level |
        {
          file:
            (($r.locations[0].physicalLocation.artifactLocation.uri) // ""),
          line:
            (($r.locations[0].physicalLocation.region.startLine) // 0),
          severity:
            (
              if   $level == "error"   then "critical"
              elif $level == "warning" then "high"
              elif $level == "note"    then "medium"
              elif $level == "none"    then "low"
              else                          "low"
              end
            ),
          cwe:
            (
              (($rule.properties.cwe // [])) as $direct_cwe |
              (($rule.properties.tags // []) | map(select(type == "string" and startswith("CWE-"))))
                  as $tag_cwe |
              if   ($direct_cwe | length) > 0 then $direct_cwe[0]
              elif ($tag_cwe    | length) > 0 then $tag_cwe[0]
              else                                 ""
              end
            ),
          description:
            (
              ("[snyk-code] " + (($r.message.text) // ""))[0:200]
            )
        }
      ]
    ' "$SARIF_FILE"
)" || {
    printf '%s\n' "error: jq failed parsing $SARIF_FILE" >&2
    exit 3
}

# --------------------------------------------------------------------------------------------
# Stage 4b — Snyk deps JSON -> finding objects
# --------------------------------------------------------------------------------------------
#
# Per AAP §0.6.3 mapping table:
#   file        = vulnerabilities[].from[0] (typically the manifest path that introduced the
#                 vulnerable package); falls back to .packageManager; falls back to "Cargo.toml".
#   line        = always 0 (integer) per the user directive — Snyk OSS findings have no natural
#                 line origin.
#   severity    = vulnerabilities[].severity, passed through unchanged.
#                 Snyk's vocabulary (critical|high|medium|low) is already the output union.
#                 An absent value falls back to "low".
#   cwe         = prefer identifiers.CVE[0]; fall back to identifiers.CWE[0]; else empty string.
#                 The output field is named `cwe` but the user directive permits CVE values in
#                 this slot for dependency findings.
#   description = "[snyk-deps] " + (title // ""), truncated to 200 Unicode scalars via jq's
#                 `.[0:200]` slicing (preserves UTF-8).
#
# Edge case: Snyk's `snyk sbom test --json` output may wrap vulnerabilities under a different
# top-level key (e.g., a SARIF-style envelope). This script targets the `snyk test --json`
# schema where vulnerabilities live at `.vulnerabilities`. If a future schema change moves them,
# this jq filter must be updated accordingly.

DEPS_FINDINGS="$(
    jq -c '
      [
        (.vulnerabilities // []) | .[]? as $v |
        {
          file:
            (
              if   (($v.from // []) | length) > 0 then ($v.from[0])
              elif ($v.packageManager // "") != "" then ($v.packageManager)
              else                                       "Cargo.toml"
              end
            ),
          line: 0,
          severity:
            (
              if   ($v.severity // "") == "critical" then "critical"
              elif ($v.severity // "") == "high"     then "high"
              elif ($v.severity // "") == "medium"   then "medium"
              elif ($v.severity // "") == "low"      then "low"
              else                                        "low"
              end
            ),
          cwe:
            (
              (($v.identifiers.CVE // [])) as $cve |
              (($v.identifiers.CWE // [])) as $cwe |
              if   ($cve | length) > 0 then $cve[0]
              elif ($cwe | length) > 0 then $cwe[0]
              else                          ""
              end
            ),
          description:
            (
              ("[snyk-deps] " + (($v.title) // ""))[0:200]
            )
        }
      ]
    ' "$DEPS_FILE"
)" || {
    printf '%s\n' "error: jq failed parsing $DEPS_FILE" >&2
    exit 3
}

# --------------------------------------------------------------------------------------------
# Stage 4c — concatenate (SAST first, deps second; natural order, no sort)
# --------------------------------------------------------------------------------------------
#
# `jq -n -c --argjson a '...' --argjson b '...' '$a + $b'` concatenates the two arrays into a
# single array. The resulting JSON is a single-line, minified array. `jq -c` does NOT append a
# trailing newline; the trailing newline that satisfies the `wc -l = 1` gate is appended by an
# explicit `printf '\n'` immediately after.

MERGED="$(
    jq -n -c \
        --argjson sast "$SAST_FINDINGS" \
        --argjson deps "$DEPS_FINDINGS" \
        '$sast + $deps'
)" || {
    printf '%s\n' "error: jq failed concatenating SAST and deps arrays" >&2
    exit 3
}

# --------------------------------------------------------------------------------------------
# Emit
# --------------------------------------------------------------------------------------------

printf '%s\n' "$MERGED"
