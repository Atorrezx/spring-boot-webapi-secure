#!/usr/bin/env python3
"""Assert-based tests for quality_gate.py (no pytest needed)."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quality_gate as qg  # noqa: E402

SEMGREP = {"results": [
    {"check_id": "r.err", "path": "A.java", "start": {"line": 3}, "extra": {"severity": "ERROR"}},
    {"check_id": "r.warn", "path": "B.java", "start": {"line": 9}, "extra": {"severity": "WARNING"}},
]}
SPOTBUGS = ('<BugCollection><BugInstance type="SQL_INJECTION" rank="3" category="SECURITY" priority="2">'
            '<Class classname="a.A"/></BugInstance>'
            '<BugInstance type="DM_X" rank="15" category="PERFORMANCE" priority="3">'
            '<Class classname="a.B"/></BugInstance></BugCollection>')
DC = {"dependencies": [{"fileName": "commons-text-1.9.jar", "vulnerabilities": [
    {"name": "CVE-1", "severity": "CRITICAL", "cvssv3": {"baseScore": 9.8}},
    {"name": "CVE-2", "severity": "MEDIUM", "cvssv3": {"baseScore": 5.0}},
]}]}

with tempfile.TemporaryDirectory() as d:
    def w(name, content):
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
        return p

    sg, sb, dc = w("sg.json", SEMGREP), w("sb.xml", SPOTBUGS), w("dc.json", DC)
    assert qg.semgrep(sg) == ["r.err A.java:3"]
    assert qg.spotbugs(sb) == ["SQL_INJECTION a.A"]
    assert qg.dependency_check(dc, 9.0) == ["CVE-1 commons-text-1.9.jar"]

    assert qg.main(["--semgrep", sg]) == 1
    assert qg.main(["--spotbugs", sb]) == 1
    assert qg.main(["--dependency-check", dc]) == 1

    clean_sg = w("c.json", {"results": []})
    clean_sb = w("c.xml", "<BugCollection/>")
    clean_dc = w("cd.json", {"dependencies": [{"fileName": "x.jar"}]})
    assert qg.main(["--semgrep", clean_sg, "--spotbugs", clean_sb, "--dependency-check", clean_dc]) == 0

    assert qg.main([]) == 0
    assert qg.main(["--semgrep", os.path.join(d, "nope.json")]) == 0

print("OK")
