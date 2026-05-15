#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_sonarqube_scan.sh
#
# Ephemeral SonarQube Community Build scan driver for the
# blitzy-tgr-dnsmasq-rust Rust workspace (Config I of the multi-config
# security-tool comparison).
#
# This script is the auditable record of how findings-config-i.json was
# produced. It implements the user-mandated five-directive workflow
# (D1..D5) defined in:
#   blitzy/documentation/Technical Specifications.md  (Agent Action Plan, §0)
#
# Cross-reference each "CR1-#" tag below against the Checkpoint 1 AAP
# Compliance Matrix rows 16..24.
#
# Usage:
#   ./run_sonarqube_scan.sh [REPO_ROOT]
#
# REPO_ROOT defaults to the parent of this script's directory, which
# resolves to /tmp/blitzy/blitzy-tgr-dnsmasq-rust/<branch>/.
#
# Exit codes:
#   0  Pipeline completed; findings-config-i.json is current
#   2  Bad arguments or missing host tooling
#   3  SonarQube backend failed to reach status UP within 120 s
#   4  sonar-scanner returned non-zero (scan failure or quality-gate failure)
#   5  Findings harvest / normalization failed
#
# Idempotency: a trap registered at the very top of the script ensures the
# sonarqube-test container is stopped and removed on every exit path, even
# on signal-driven termination. (CR1-24)
# ---------------------------------------------------------------------------

set -o errexit
set -o nounset
set -o pipefail

# ---------------------------------------------------------------------------
# CR1-24: Idempotent teardown trap registered at top of script.
#
# Both subcommands are silenced because the container may not exist if the
# pull or run step itself failed before reaching docker run. The trap fires
# on EXIT (normal or error), INT (Ctrl-C), TERM (kill), and HUP.
# ---------------------------------------------------------------------------
trap '
  docker stop  sonarqube-test >/dev/null 2>&1 || true
  docker rm -f sonarqube-test >/dev/null 2>&1 || true
' EXIT INT TERM HUP

# ---------------------------------------------------------------------------
# Constants.
#
# The container name (sonarqube-test), the host port (9000), the image tag
# (sonarqube:community), the project key (blitzy-tgr-dnsmasq-rust), and the
# credentials (admin/admin) are all taken verbatim from the user prompt and
# are not parameterized. Changing any of these would break reproducibility
# of the comparison harness.
# ---------------------------------------------------------------------------
CONTAINER_NAME='sonarqube-test'
IMAGE_TAG='sonarqube:community'
HOST_PORT='9000'
SONAR_HOST_URL="http://localhost:${HOST_PORT}"
SONAR_LOGIN='admin'
SONAR_PASSWORD='admin'
PROJECT_KEY='blitzy-tgr-dnsmasq-rust'
COLD_START_TIMEOUT_S=120

# Resolve repository root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

if [ ! -f "${REPO_ROOT}/Cargo.toml" ]; then
  echo "ERROR: REPO_ROOT ${REPO_ROOT} does not contain Cargo.toml." >&2
  exit 2
fi

PYTHON_BIN="$(command -v python3 || true)"
if [ -z "${PYTHON_BIN}" ]; then
  echo "ERROR: python3 is required but not on PATH." >&2
  exit 2
fi

OUTPUT_FILE="${REPO_ROOT}/findings-config-i.json"
PIPELINE_SCRIPT="${SCRIPT_DIR}/sonar_pipeline.py"
PROPERTIES_FILE="${SCRIPT_DIR}/sonar-project.properties"

echo "==> Config I scan starting"
echo "    REPO_ROOT       = ${REPO_ROOT}"
echo "    OUTPUT_FILE     = ${OUTPUT_FILE}"
echo "    SONAR_HOST_URL  = ${SONAR_HOST_URL}"
echo "    CONTAINER_NAME  = ${CONTAINER_NAME}"
echo "    IMAGE_TAG       = ${IMAGE_TAG}"

# ===========================================================================
# D1: Install sonar-scanner and pull the sonarqube:community image.
#
# Both invocations match the user examples verbatim. The image-pull duration
# is captured for the executive summary (Checkpoint 2 decision log).
# ===========================================================================
echo "==> D1: Installing host tooling"

# Install sonar-scanner via apt (idempotent: skipped if already installed).
if ! command -v sonar-scanner >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y sonar-scanner
fi

# Sanity check per the user D1 pass criterion.
sonar-scanner --version

# Pull the image and time it (CR1-23 telemetry source).
echo "==> D1: docker pull ${IMAGE_TAG}"
PULL_START_S=$(date +%s)
docker pull "${IMAGE_TAG}"
PULL_END_S=$(date +%s)
IMAGE_PULL_TIME_S=$(( PULL_END_S - PULL_START_S ))

# Capture the resolved image digest for the audit trail.
IMAGE_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE_TAG}" 2>/dev/null || echo "${IMAGE_TAG}")"
echo "    image digest    = ${IMAGE_DIGEST}"
echo "    image pull time = ${IMAGE_PULL_TIME_S}s"

# ===========================================================================
# D2: Start the SonarQube container detached and poll /api/system/status
# until the server reports UP, with a hard 120-second timeout.
# ===========================================================================
echo "==> D2: Starting ephemeral SonarQube backend"

# In the rare case a prior run left a stopped container around, remove it
# first so docker run does not fail with "name already in use".
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${HOST_PORT}:9000" \
  "${IMAGE_TAG}" >/dev/null

# ---------------------------------------------------------------------------
# CR1-23: Cold-start polling per AAP §0.5.6.6.
#
# curl is invoked with both --connect-timeout (network-level) and
# --max-time (whole-request), so a hung server cannot stall the poll loop.
# The accepted intermediate states are STARTING, DB_MIGRATION_NEEDED, and
# DB_MIGRATION_RUNNING. The single failure state is DOWN. The single
# success state is UP. Any other state is treated as transient and is
# retried up to the cumulative 120-second budget.
# ---------------------------------------------------------------------------
POLL_START_S=$(date +%s)
COLD_START_TIME_S=-1
while true; do
  now_s=$(date +%s)
  elapsed_s=$(( now_s - POLL_START_S ))
  if [ "${elapsed_s}" -ge "${COLD_START_TIMEOUT_S}" ]; then
    echo "ERROR: SonarQube did not reach UP within ${COLD_START_TIMEOUT_S}s." >&2
    exit 3
  fi

  status_json="$(
    curl --silent --show-error --fail \
         --connect-timeout 2 --max-time 5 \
         "${SONAR_HOST_URL}/api/system/status" 2>/dev/null || true
  )"

  status="$(
    printf '%s' "${status_json}" \
      | "${PYTHON_BIN}" -c 'import json,sys
try:
    print(json.loads(sys.stdin.read() or "{}").get("status", "PENDING"))
except json.JSONDecodeError:
    print("PENDING")' 2>/dev/null || echo "PENDING"
  )"

  case "${status}" in
    UP)
      COLD_START_TIME_S=${elapsed_s}
      echo "    SonarQube is UP after ${COLD_START_TIME_S}s"
      break
      ;;
    DOWN)
      echo "ERROR: SonarQube reported status DOWN." >&2
      exit 3
      ;;
    STARTING|DB_MIGRATION_NEEDED|DB_MIGRATION_RUNNING|PENDING)
      sleep 1
      ;;
    *)
      # Unknown state: keep polling under the 120s budget rather than
      # failing fast, but log it for the decision log.
      echo "    (unrecognized status '${status}' — continuing poll)"
      sleep 1
      ;;
  esac
done

# ===========================================================================
# D3: Execute the scan.
#
# Properties are passed via -D flags (matching the user's literal D3
# invocation) and ALSO written to a sonar-project.properties side-car file
# co-located with this script for auditability. The scanner runs with the
# CWD set to REPO_ROOT so that relative paths in the scan output are
# rooted at the workspace.
# ===========================================================================
echo "==> D3: Running sonar-scanner"

# Update the properties file with the resolved absolute source path so it
# remains a faithful mirror of the -D flags actually passed below.
cat > "${PROPERTIES_FILE}" <<EOF
# Auto-regenerated by run_sonarqube_scan.sh. Edit the .sh, not this file.
sonar.projectKey=${PROJECT_KEY}
sonar.sources=${REPO_ROOT}
sonar.host.url=${SONAR_HOST_URL}
sonar.login=${SONAR_LOGIN}
sonar.password=${SONAR_PASSWORD}
sonar.qualitygate.wait=true
EOF

SCAN_START_S=$(date +%s)
set +e
sonar-scanner \
  "-Dsonar.projectKey=${PROJECT_KEY}" \
  "-Dsonar.sources=${REPO_ROOT}" \
  "-Dsonar.host.url=${SONAR_HOST_URL}" \
  "-Dsonar.login=${SONAR_LOGIN}" \
  "-Dsonar.password=${SONAR_PASSWORD}" \
  "-Dsonar.qualitygate.wait=true"
SCANNER_EXIT=$?
set -e
SCAN_END_S=$(date +%s)
SCAN_WALL_CLOCK_S=$(( SCAN_END_S - SCAN_START_S ))
echo "    sonar-scanner exit = ${SCANNER_EXIT}"
echo "    scan wall-clock    = ${SCAN_WALL_CLOCK_S}s"

# sonar-scanner returns non-zero when the quality gate fails. The user's D3
# pass criterion is "Scan completes AND the quality gate result is returned",
# so we treat a quality-gate failure as a soft fail: we still harvest the
# issue set. A scanner crash (different exit code class, no quality-gate
# JSON) is a hard fail.
if [ ${SCANNER_EXIT} -ne 0 ] && [ ${SCANNER_EXIT} -ne 1 ]; then
  echo "ERROR: sonar-scanner failed with exit code ${SCANNER_EXIT}." >&2
  exit 4
fi

# ===========================================================================
# D4 + D5: Harvest issues and normalize to the user-specified 5-field schema.
#
# All API filters, pagination logic, the 10k fallback, the severity remap,
# the CWE cascade, the .rs path filter, the positive-line filter, the
# code-point truncation, and the minified JSON serialization live in the
# Python pipeline module to keep the bash driver thin and the safeguards
# testable in isolation.
#
# Cross-references:
#   CR1-16  Severity remap with hard error           -> sonar_pipeline.py: SEVERITY_REMAP / normalize_severity
#   CR1-17  CWE cascade with memoized rule lookup     -> sonar_pipeline.py: CweResolver.resolve
#   CR1-18  Component prefix strip + .rs filter       -> sonar_pipeline.py: normalize_component
#   CR1-19  Positive-integer line filter              -> sonar_pipeline.py: normalize_line
#   CR1-20  Code-point truncation (no ellipsis)       -> sonar_pipeline.py: truncate_description
#   CR1-21  ps=500 pagination with types filter       -> sonar_pipeline.py: fetch_issues_page
#   CR1-22  paging.total >= 10000 fallback            -> sonar_pipeline.py: harvest_issues
# ===========================================================================
echo "==> D4 + D5: Harvesting and normalizing findings"

"${PYTHON_BIN}" "${PIPELINE_SCRIPT}" \
  --host-url   "${SONAR_HOST_URL}" \
  --login      "${SONAR_LOGIN}" \
  --password   "${SONAR_PASSWORD}" \
  --project-key "${PROJECT_KEY}" \
  --output     "${OUTPUT_FILE}"

# ===========================================================================
# D5: Teardown.
#
# The trap registered at the top of the script will run docker stop + rm on
# EXIT, so the explicit teardown commands below are redundant but match the
# user's literal D5 example. Both forms guarantee the container is gone.
# ===========================================================================
echo "==> D5: Tearing down"
docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker rm   "${CONTAINER_NAME}" >/dev/null 2>&1 || true

# Telemetry summary for the decision-log header (Checkpoint 2 deliverable).
echo ""
echo "==> Telemetry"
echo "    image_digest         = ${IMAGE_DIGEST}"
echo "    image_pull_time_s    = ${IMAGE_PULL_TIME_S}"
echo "    cold_start_time_s    = ${COLD_START_TIME_S}"
echo "    scan_wall_clock_s    = ${SCAN_WALL_CLOCK_S}"
echo "    scanner_exit         = ${SCANNER_EXIT}"
echo "    output_file          = ${OUTPUT_FILE}"
echo "    output_size_bytes    = $(wc -c <"${OUTPUT_FILE}")"
echo "    output_line_count    = $(wc -l <"${OUTPUT_FILE}")"

echo "==> Config I scan complete"
