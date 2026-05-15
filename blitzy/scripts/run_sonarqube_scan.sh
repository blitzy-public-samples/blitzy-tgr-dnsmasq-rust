#!/usr/bin/env bash
# run_sonarqube_scan.sh
#
# Driver for the ephemeral SonarQube Community Build scan that produces
# findings-config-i.json. Implements directives D1..D5 from AAP §0.
#
# Usage:
#   ./run_sonarqube_scan.sh [REPO_ROOT]
#
# Exit codes:
#   0  Pipeline completed
#   2  Bad arguments or missing host tooling
#   3  SonarQube backend did not reach status UP within 120 s
#   4  sonar-scanner returned non-zero
#   5  Findings harvest / normalization failed
#
# All rationale for every decision below lives in decision-log-config-i.md
# per the Explainability rule (AAP §0.7.1).

set -o errexit
set -o nounset
set -o pipefail

# Bring cargo onto PATH if rustup is installed.
if [ -f "${HOME:-/root}/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "${HOME:-/root}/.cargo/env"
fi

# Resolve repository root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${1:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"

# Constants.
CONTAINER_NAME='sonarqube-test'
IMAGE_TAG='sonarqube:community'
HOST_PORT='9000'
SONAR_HOST_URL="http://localhost:${HOST_PORT}"
SONAR_LOGIN='admin'
SONAR_PASSWORD='admin'
PROJECT_KEY='blitzy-tgr-dnsmasq-rust'
COLD_START_TIMEOUT_S=120

PROPERTIES_FILE="${SCRIPT_DIR}/sonar-project.properties"

# Idempotent teardown trap. Runs on EXIT, INT, TERM, HUP.
trap '
  docker stop  sonarqube-test >/dev/null 2>&1 || true
  docker rm -f sonarqube-test >/dev/null 2>&1 || true
  rm -f "'"${PROPERTIES_FILE}"'" 2>/dev/null || true
' EXIT INT TERM HUP

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

echo "==> Config I scan starting"
echo "    REPO_ROOT       = ${REPO_ROOT}"
echo "    OUTPUT_FILE     = ${OUTPUT_FILE}"
echo "    SONAR_HOST_URL  = ${SONAR_HOST_URL}"
echo "    CONTAINER_NAME  = ${CONTAINER_NAME}"
echo "    IMAGE_TAG       = ${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# D1: install sonar-scanner and pull the sonarqube:community image.
# ---------------------------------------------------------------------------
echo "==> D1: Installing host tooling"

if ! command -v sonar-scanner >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y sonar-scanner
fi

sonar-scanner --version

echo "==> D1: docker pull ${IMAGE_TAG}"
PULL_START_S=$(date +%s)
docker pull "${IMAGE_TAG}"
PULL_END_S=$(date +%s)
IMAGE_PULL_TIME_S=$(( PULL_END_S - PULL_START_S ))

IMAGE_DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE_TAG}" 2>/dev/null || echo "${IMAGE_TAG}")"
echo "    image digest    = ${IMAGE_DIGEST}"
echo "    image pull time = ${IMAGE_PULL_TIME_S}s"

# ---------------------------------------------------------------------------
# D2: start the SonarQube container and poll /api/system/status until UP.
# ---------------------------------------------------------------------------
echo "==> D2: Starting ephemeral SonarQube backend"

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  -p "${HOST_PORT}:9000" \
  "${IMAGE_TAG}" >/dev/null

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
      echo "    (unrecognized status '${status}' - continuing poll)"
      sleep 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Mint a short-lived global analysis token from admin/admin.
# ---------------------------------------------------------------------------
echo "==> Minting ephemeral scanner token"
TOKEN_NAME="config-i-scan-$(date +%s)"

curl --silent --show-error --fail \
     --connect-timeout 2 --max-time 10 \
     -u "${SONAR_LOGIN}:${SONAR_PASSWORD}" \
     -X POST \
     --data-urlencode "name=${TOKEN_NAME}" \
     "${SONAR_HOST_URL}/api/user_tokens/revoke" \
     >/dev/null 2>&1 || true

TOKEN_RESPONSE="$(
  curl --silent --show-error --fail \
       --connect-timeout 2 --max-time 10 \
       -u "${SONAR_LOGIN}:${SONAR_PASSWORD}" \
       -X POST \
       --data-urlencode "name=${TOKEN_NAME}" \
       --data-urlencode "type=GLOBAL_ANALYSIS_TOKEN" \
       "${SONAR_HOST_URL}/api/user_tokens/generate"
)"

SONAR_TOKEN="$(
  printf '%s' "${TOKEN_RESPONSE}" \
    | "${PYTHON_BIN}" -c 'import json,sys
try:
    print(json.loads(sys.stdin.read() or "{}").get("token", ""))
except json.JSONDecodeError:
    print("")' 2>/dev/null
)"

if [ -z "${SONAR_TOKEN}" ]; then
  echo "ERROR: /api/user_tokens/generate returned no token. Response was: ${TOKEN_RESPONSE}" >&2
  exit 4
fi
echo "    token name = ${TOKEN_NAME}"

# ---------------------------------------------------------------------------
# D3: execute the scan.
# ---------------------------------------------------------------------------
echo "==> D3: Running sonar-scanner"

cat > "${PROPERTIES_FILE}" <<EOF
# Auto-regenerated by run_sonarqube_scan.sh; transient (gitignored).
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
  "-Dsonar.token=${SONAR_TOKEN}" \
  "-Dsonar.qualitygate.wait=true"
SCANNER_EXIT=$?
set -e
SCAN_END_S=$(date +%s)
SCAN_WALL_CLOCK_S=$(( SCAN_END_S - SCAN_START_S ))
echo "    sonar-scanner exit = ${SCANNER_EXIT}"
echo "    scan wall-clock    = ${SCAN_WALL_CLOCK_S}s"

if [ ${SCANNER_EXIT} -ne 0 ] && [ ${SCANNER_EXIT} -ne 1 ]; then
  echo "ERROR: sonar-scanner failed with exit code ${SCANNER_EXIT}." >&2
  exit 4
fi

# ---------------------------------------------------------------------------
# D4 + D5: harvest issues and normalize to the 5-field schema.
# ---------------------------------------------------------------------------
echo "==> D4 + D5: Harvesting and normalizing findings"

"${PYTHON_BIN}" "${PIPELINE_SCRIPT}" \
  --host-url   "${SONAR_HOST_URL}" \
  --login      "${SONAR_LOGIN}" \
  --password   "${SONAR_PASSWORD}" \
  --project-key "${PROJECT_KEY}" \
  --output     "${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# D5: explicit teardown.
# ---------------------------------------------------------------------------
echo "==> D5: Tearing down"
docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker rm   "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo ""
echo "==> Telemetry"
echo "    image_digest         = ${IMAGE_DIGEST}"
echo "    image_pull_time_s    = ${IMAGE_PULL_TIME_S}"
echo "    cold_start_time_s    = ${COLD_START_TIME_S}"
echo "    scanner_token_name   = ${TOKEN_NAME}"
echo "    scan_wall_clock_s    = ${SCAN_WALL_CLOCK_S}"
echo "    scanner_exit         = ${SCANNER_EXIT}"
echo "    output_file          = ${OUTPUT_FILE}"
echo "    output_size_bytes    = $(wc -c <"${OUTPUT_FILE}")"
echo "    output_line_count    = $(wc -l <"${OUTPUT_FILE}")"

echo "==> Config I scan complete"
