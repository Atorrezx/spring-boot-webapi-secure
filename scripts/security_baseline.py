#!/usr/bin/env python3
"""Paired, filesystem-only scanner runner for the security-baseline workflow."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

MAVEN = "maven:3.9-eclipse-temurin-21"
SEMGREP = "semgrep/semgrep:1.178.0"
CONFTEST = "openpolicyagent/conftest:v0.57.0"
TRIVY = "aquasec/trivy:0.70.0"
REPORTS = {"dependency-check-report.sarif", "spotbugs-report.json", "semgrep-results.json", "trivy-report.json", "conftest-report.json"}


def run(*args, check=True, **kwargs):
    return subprocess.run(args, text=True, check=check, **kwargs)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def docker_digest(image):
    run("docker", "pull", image)
    return run("docker", "image", "inspect", "--format={{index .RepoDigests 0}}", image,
               capture_output=True).stdout.strip()


def archive(revision, destination):
    destination.mkdir(parents=True, exist_ok=True)
    payload = run("git", "archive", revision, stdout=subprocess.PIPE).stdout
    run("tar", "-x", "-C", str(destination), input=payload)


def scan_pom(source, refresh_db=False):
    """Copy the source POM and set audit-only, secret-free scanner configuration."""
    pom = source / "pom.xml"
    tree = ET.parse(pom)
    root = tree.getroot()
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    ET.register_namespace("", ns["m"])
    for plugin in root.findall(".//m:plugin", ns):
        artifact = plugin.find("m:artifactId", ns)
        if artifact is None:
            continue
        config = plugin.find("m:configuration", ns)
        if config is None:
            config = ET.SubElement(plugin, "{%s}configuration" % ns["m"])
        name = artifact.text
        pins = {"dependency-check-maven": "11.1.1", "spotbugs-maven-plugin": "4.8.6.2"}
        if name in pins:
            version = plugin.find("m:version", ns)
            if version is None: version = ET.SubElement(plugin, "{%s}version" % ns["m"])
            version.text = pins[name]
        if name == "dependency-check-maven":
            for item in list(config):
                if item.tag.rsplit("}", 1)[-1] in {"nvdApiKey", "autoUpdate", "failBuildOnCVSS", "failOnError", "skipTestScope", "ossindexAnalyzerEnabled", "formats"}:
                    config.remove(item)
            for tag, value in (("nvdApiKey", "${env.NVD_API_KEY}"), ("autoUpdate", str(bool(refresh_db)).lower()),
                               ("failBuildOnCVSS", "11"), ("failOnError", "true"), ("skipTestScope", "true"), ("ossindexAnalyzerEnabled", "false")):
                ET.SubElement(config, "{%s}%s" % (ns["m"], tag)).text = value
            formats = ET.SubElement(config, "{%s}formats" % ns["m"])
            for value in ("HTML", "JSON", "XML", "SARIF"):
                ET.SubElement(formats, "{%s}format" % ns["m"]).text = value
        if name == "spotbugs-maven-plugin":
            for tag, value in (("xmlOutput", "true"), ("sarifOutput", "true"), ("sarifOutputFilename", "spotbugs-report.json"), ("failOnError", "true")):
                item = config.find("m:" + tag, ns)
                if item is None: item = ET.SubElement(config, "{%s}%s" % (ns["m"], tag))
                item.text = value
    target = source / "pom.scan.xml"
    tree.write(target, encoding="utf-8", xml_declaration=True)
    return target


def sarif(value, name):
    if value.get("version") != "2.1.0" or not isinstance(value.get("runs"), list) or not value["runs"]:
        raise ValueError("invalid " + name + " SARIF")


def conftest_valid(value, require_finding=False):
    if not isinstance(value, list) or not value:
        raise ValueError("invalid Conftest JSON")
    findings = 0
    for result in value:
        if not isinstance(result, dict) or not isinstance(result.get("successes"), int) or isinstance(result["successes"], bool):
            raise ValueError("Conftest successes must be an integer")
        for key in ("failures", "warnings"):
            items = result.get(key, [])
            if not isinstance(items, list): raise ValueError("invalid Conftest " + key)
            findings += len(items)
    if require_finding and not findings: raise ValueError("Conftest exit 1 without findings")
    return findings


def validate(path):
    path = Path(path)
    missing = REPORTS - {item.name for item in path.iterdir()} if path.exists() else REPORTS
    if missing:
        raise ValueError("missing reports: " + ", ".join(sorted(missing)))
    dependency_sarif = json.loads((path / "dependency-check-report.sarif").read_text())
    spotbugs = json.loads((path / "spotbugs-report.json").read_text())
    semgrep = json.loads((path / "semgrep-results.json").read_text())
    trivy = json.loads((path / "trivy-report.json").read_text())
    conftest = json.loads((path / "conftest-report.json").read_text())
    sarif(dependency_sarif, "Dependency-Check"); sarif(spotbugs, "SpotBugs")
    if not isinstance(semgrep.get("results"), list) or semgrep.get("errors"):
        raise ValueError("invalid Semgrep JSON")
    conftest_findings = conftest_valid(conftest)
    if not isinstance(trivy.get("Results"), list):
        raise ValueError("invalid Trivy JSON")
    libraries = [p for result in trivy["Results"] for p in result.get("Packages", [])]
    if not libraries:
        raise ValueError("Trivy has no library inventory")
    for result in conftest:
        if "successes" in result and not isinstance(result["successes"], int):
            raise ValueError("Conftest successes must be an integer")
    dc_native = path / "dependency-check-report.native.json"
    if not dc_native.exists() or not isinstance(json.loads(dc_native.read_text()).get("dependencies"), list):
        raise ValueError("missing Dependency-Check dependency inventory")
    return {"dependency-check": sum(len(r.get("results", [])) for r in dependency_sarif["runs"]),
            "spotbugs": sum(len(r.get("results", [])) for r in spotbugs["runs"]),
            "semgrep": len(semgrep["results"]), "trivy-packages": len(libraries),
            "trivy": sum(len(r.get("Vulnerabilities") or []) for r in trivy["Results"]),
            "conftest": conftest_findings}


def scan(source, output, controls, refresh_db=False):
    """Run native Docker scanners, retaining output even when one scanner fails."""
    source, output = Path(source), Path(output)
    status = 0
    statuses = []
    def docker(image, *command, secret=False, allowed=(0,), capture=False):
        nonlocal status
        if secret and not os.environ.get("NVD_API_KEY"): raise ValueError("NVD_API_KEY is required")
        env = dict(os.environ); env.update({"NVD_API_KEY": os.environ["NVD_API_KEY"]} if secret else {})
        result = run("docker", "run", "--pull=never", "--rm", *( ("-e", "NVD_API_KEY") if secret else ()),
                     "-v", f"{source.resolve()}:/src", "-v", f"{Path(controls).resolve()}:/controls:ro",
                     "-v", f"{Path.home() / '.m2'}:/root/.m2", "-v", f"{Path.home() / '.cache/trivy'}:/root/.cache/trivy",
                     "-w", "/src", image, *command, check=False, env=env, capture_output=capture)
        status |= result.returncode not in allowed
        statuses.append({"image": image, "command": list(command), "returncode": result.returncode})
        return result
    if refresh_db:
        docker(TRIVY, "image", "--download-db-only")
        docker(TRIVY, "image", "--download-java-db-only")
    docker(MAVEN, "mvn", "-B", "-f", "pom.scan.xml", "package", "-DskipTests")
    docker(MAVEN, "mvn", "-B", "-f", "pom.scan.xml", "dependency-check:check", secret=True)
    docker(MAVEN, "mvn", "-B", "-f", "pom.scan.xml", "spotbugs:spotbugs")
    for source_name, target_name in (("dependency-check-report.sarif", "dependency-check-report.sarif"),
                                     ("spotbugs-report.json", "spotbugs-report.json"),
                                     ("dependency-check-report.json", "dependency-check-report.native.json"),
                                     ("spotbugsXml.xml", "spotbugs-report.native.xml")):
        candidate = source / "target" / source_name
        if candidate.exists(): shutil.copy2(candidate, output / target_name)
    docker(SEMGREP, "semgrep", "scan", "--config", "/controls/java.yml", "--config", "/controls/.semgrep.yml", "--metrics=off", "--json-output", "/src/semgrep-results.json", "/src/src/main/java")
    docker(TRIVY, "rootfs", "--scanners", "vuln", "--pkg-types", "library", "--list-all-pkgs", "--format", "json", "--output", "trivy-report.json", "--skip-db-update", "--skip-java-db-update", "target")
    conftest = docker(CONFTEST, "test", "--policy", "/controls/policies/dockerfile.rego", "--output", "json", "/src/Dockerfile", allowed=(0, 1), capture=True)
    (output / "conftest-report.json").write_text(conftest.stdout)
    if conftest.returncode == 1:
        try: conftest_valid(json.loads(conftest.stdout), require_finding=True)
        except (ValueError, json.JSONDecodeError): status = 1
    for name in ("semgrep-results.json", "trivy-report.json"):
        candidate = source / name
        if candidate.exists(): shutil.move(candidate, output / name)
    trivy_metadata = [{"path": str(item), "sha256": sha256(item), "mtime": item.stat().st_mtime}
                      for item in (Path.home() / ".cache/trivy").rglob("metadata.json")]
    dc_info = {}
    dc_report = output / "dependency-check-report.native.json"
    if dc_report.exists(): dc_info = json.loads(dc_report.read_text()).get("scanInfo", {})
    (output / "db-metadata.json").write_text(json.dumps({"trivy": trivy_metadata, "dependency_check": dc_info}, indent=2) + "\n")
    (output / "process-status.json").write_text(json.dumps(statuses, indent=2) + "\n")
    return int(status)


def manifest(output, revision, images, controls, source=None, tree=None):
    counts = validate(output)
    data = {"revision": revision, "tree": tree, "created_at": datetime.now(timezone.utc).isoformat(),
            "scope": "rootfs scan of compiled application JAR directory; library packages only, no image or OS packages",
            "source_pom_sha256": sha256(Path(source) / "pom.xml") if source else None,
            "images": images, "controls": {name: sha256(file) for name, file in controls.items()},
            "reports": {name: sha256(output / name) for name in sorted(REPORTS)}, "db_metadata": json.loads((output / "db-metadata.json").read_text()), "process_statuses": json.loads((output / "process-status.json").read_text()), "counts": counts}
    (output / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    overlay = sub.add_parser("overlay"); overlay.add_argument("source"); overlay.add_argument("--refresh-db", action="store_true")
    check = sub.add_parser("validate"); check.add_argument("output")
    scanner = sub.add_parser("scan"); scanner.add_argument("source"); scanner.add_argument("output"); scanner.add_argument("--controls", required=True); scanner.add_argument("--refresh-db", action="store_true")
    record = sub.add_parser("manifest"); record.add_argument("output"); record.add_argument("revision")
    record.add_argument("--image", action="append", default=[]); record.add_argument("--images-file"); record.add_argument("--control", action="append", default=[]); record.add_argument("--source"); record.add_argument("--tree")
    args = parser.parse_args(argv)
    if args.cmd == "overlay": print(scan_pom(Path(args.source), args.refresh_db))
    elif args.cmd == "validate": print(json.dumps(validate(args.output), sort_keys=True))
    elif args.cmd == "scan": sys.exit(scan(args.source, args.output, args.controls, args.refresh_db))
    else:
        image_lines = args.image + (Path(args.images_file).read_text().splitlines() if args.images_file else [])
        images = dict(item.split("=", 1) for item in image_lines)
        controls = dict(item.split("=", 1) for item in args.control)
        manifest(Path(args.output), args.revision, images, controls, args.source, args.tree)

if __name__ == "__main__":
    main()
