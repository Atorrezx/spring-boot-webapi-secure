# Paired filesystem security baseline

`paired-security-baseline.yml` runs five native scanners against two immutable Git
archives: before `584fd8d9b9ce6d1ac4ef6d41cfbabc0f0f7ae3dc` and after
`df8e9e38f0ca890be73748024e12b22173968264`. It is an audit workflow, not a
source gate, deployment, image scan, or application start.

## Run and collect

The workflow runs on a push to `ci/paired-security-baseline`; it may also be
manually dispatched after that workflow exists remotely. Download the separate
14-day `paired-before-*` and `paired-after-*` artifacts. Actual remote execution
is pending publication and dispatch by the parent maintainer.

Each revision artifact contains these DefectDojo imports:

| File | DefectDojo scan type |
|---|---|
| `dependency-check-report.sarif` | SARIF |
| `spotbugs-report.json` | SARIF |
| `semgrep-results.json` | Semgrep JSON Report |
| `trivy-report.json` | Trivy Scan |
| `conftest-report.json` | Conftest Scan |

`manifest.json` records frozen revisions, image digests, control hashes, report
hashes, counts, and creation time. Dependency-Check JSON and SpotBugs XML are
auxiliary native evidence, not converted substitutes.

## Scope and limits

Maven builds an ephemeral archive with `pom.scan.xml`; the original POM and
source checkout are never edited. The overlay replaces any embedded NVD key with
`${env.NVD_API_KEY}` and receives the Actions secret only inside Maven Docker.
Trivy scans compiled application artifacts and dependency libraries, not the
original Docker image, OS packages, or `libpng`. Semgrep freezes the community
Java rules and the after-revision local rule once, then reuses them for both
archives. Conftest evaluates the unchanged Dockerfile policy; a valid zero
failure result does not prove build success.

Scanner findings are data. Missing, malformed, or empty-inventory reports and
fatal scanner errors fail the workflow; results are compared per tool rather
than through a cross-tool total or assumed DefectDojo deduplication.
