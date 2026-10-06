#!/usr/bin/env bash
# Runs Semgrep, Maven build + SpotBugs and (optionally) Dependency-Check via Docker.
# Reports go to evidencias/local/. Run from anywhere; the repo root is auto-detected.
set -uo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
ROOT="$(pwd -W 2>/dev/null || pwd)"
OUT=evidencias/local
mkdir -p "$OUT"

MVN_IMAGE=maven:3.9-eclipse-temurin-21
mvn_docker() {
  docker run --rm -v "$ROOT:/repo" -v m2-cache:/root/.m2 -w /repo "$MVN_IMAGE" mvn -B "$@"
}

echo "==> Semgrep"
docker run --rm -v "$ROOT:/src" -w /src semgrep/semgrep \
  semgrep scan --config auto --config .semgrep.yml --metrics=on \
  --json-output="$OUT/semgrep-results.json" \
  --sarif-output="$OUT/semgrep-results.sarif" \
  src/main/java 2>&1 | tee "$OUT/semgrep.txt"

echo "==> Maven build + SpotBugs"
mvn_docker clean verify spotbugs:spotbugs
cp target/spotbugsXml.xml "$OUT/" 2>/dev/null || echo "WARNING: spotbugsXml.xml not produced"

DC_ARGS=()
if [ -n "${NVD_API_KEY:-}" ]; then
  echo "==> Dependency-Check"
  mvn_docker org.owasp:dependency-check-maven:check "-DnvdApiKey=$NVD_API_KEY"
  cp target/dependency-check-report.html target/dependency-check-report.json "$OUT/" 2>/dev/null
  DC_ARGS=(--dependency-check "$OUT/dependency-check-report.json")
else
  echo "==> Dependency-Check skipped (NVD_API_KEY not set)"
fi

echo "==> Quality gate"
python scripts/quality_gate.py \
  --semgrep "$OUT/semgrep-results.json" \
  --spotbugs "$OUT/spotbugsXml.xml" \
  "${DC_ARGS[@]}" 2>&1 | tee "$OUT/quality-gate.txt"
exit "${PIPESTATUS[0]}"
