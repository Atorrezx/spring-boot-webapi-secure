# Security JSON reports

The CI/CD workflow publishes native scanner output so a failed security control still leaves evidence for inspection.

## Artifacts

| Artifact name | Files | When available |
|---|---|---|
| `semgrep-reports` | `semgrep-results.json`, `semgrep-results.sarif` | The existing Semgrep job always uploads it. `scripts/quality_gate.py` continues to consume `semgrep-results.json`. |
| `trivy-reports` | `trivy-report.json`, `trivy-results.sarif` | The Docker scan always uploads both files, including after the CRITICAL/HIGH SARIF gate fails. |
| `conftest-report` | `conftest-report.json` | The Dockerfile policy job always attempts evaluation and uploads its native JSON output when Conftest produced it. |

## CI/CD behavior

Trivy runs twice against the first concrete tag from `docker/metadata-action`'s JSON output, rather than its multiline `tags` output. The first scan writes native JSON for all severity levels. The SARIF scan limits results to CRITICAL and HIGH before failing on those findings, which prevents the image push while `if: always()` uploads the reports.

Conftest `v0.57.0` evaluates the parsed `Dockerfile` and checks only its final stage. The policy requires an effective literal non-root `USER` and a real `HEALTHCHECK`; final `USER root`, `USER root:group`, UID 0 textual forms, unresolved `$VARIABLE` values, missing controls, and `HEALTHCHECK NONE` fail. The policy does not resolve Dockerfile `ARG` values, so the final `USER` must be a literal non-root value. The last final-stage instruction wins, so builder-only controls cannot satisfy the policy and a later override is detected. Unit tests run with `conftest verify --policy policies` before evaluation. Evaluation is still attempted with `if: always()` if those tests fail. The workflow publishes `conftest-report.json` only when the tool emitted nonempty parseable JSON, so a parser or tool error is not replaced with a fabricated report.

## Local verification

Use the same pinned official container image as CI:

```sh
docker run --rm -v "$PWD:/repo" -w /repo openpolicyagent/conftest:v0.57.0 verify --policy policies
docker run --rm -v "$PWD:/repo" -w /repo openpolicyagent/conftest:v0.57.0 test --policy policies --output json Dockerfile
```

The version tag is an intentional lab-level pin, not a digest guarantee. Remote GitHub Actions execution is still required to prove artifact publication and scanner behavior in the hosted workflow.
