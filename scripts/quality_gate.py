#!/usr/bin/env python3
"""Quality gate: fail (exit 1) when any scanner reports critical findings."""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET


def semgrep(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [
        f"{r['check_id']} {r['path']}:{r['start']['line']}"
        for r in data.get("results", [])
        if r.get("extra", {}).get("severity") == "ERROR"
    ]


def spotbugs(path):
    out = []
    for bug in ET.parse(path).getroot().iter("BugInstance"):
        rank = int(bug.get("rank", "20"))
        if rank <= 4 or (bug.get("category") == "SECURITY" and bug.get("priority") == "1"):
            cls = bug.find("Class")
            out.append(f"{bug.get('type')} {cls.get('classname') if cls is not None else '?'}")
    return out


def dependency_check(path, min_cvss):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            score = (v.get("cvssv3") or {}).get("baseScore", 0) or 0
            if str(v.get("severity", "")).upper() == "CRITICAL" or score >= min_cvss:
                out.append(f"{v.get('name')} {dep.get('fileName')}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--semgrep")
    ap.add_argument("--spotbugs")
    ap.add_argument("--dependency-check")
    ap.add_argument("--dc-cvss", type=float, default=9.0)
    a = ap.parse_args(argv)

    tools = [
        ("Semgrep", a.semgrep, semgrep),
        ("SpotBugs", a.spotbugs, spotbugs),
        ("Dependency-Check", a.dependency_check, lambda p: dependency_check(p, a.dc_cvss)),
    ]
    rows, details = [], {}
    for name, path, fn in tools:
        if not path or not os.path.isfile(path):
            print(f"WARNING: {name} report not found ({path or 'not provided'}); marking as not run")
            rows.append((name, "not run", 0))
            continue
        found = fn(path)
        details[name] = found
        rows.append((name, "FAIL" if found else "PASS", len(found)))

    print(f"\n{'Tool':<18}{'Status':<10}{'Critical'}")
    for name, status, n in rows:
        print(f"{name:<18}{status:<10}{n}")
    for name, found in details.items():
        for item in found:
            print(f"  [{name}] {item}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("## Quality Gate\n\n| Tool | Status | Critical |\n|---|---|---|\n")
            for name, status, n in rows:
                f.write(f"| {name} | {status} | {n} |\n")
            for name, found in details.items():
                if found:
                    f.write(f"\n**{name}**\n\n" + "".join(f"- `{i}`\n" for i in found))

    return 1 if any(n for _, _, n in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
