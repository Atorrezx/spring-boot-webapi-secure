#!/usr/bin/env python3
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import security_baseline as baseline

SARIF = {"version": "2.1.0", "runs": [{"results": []}]}

class BaselineTest(unittest.TestCase):
    def reports(self, directory, trivy=True):
        for name, value in {"dependency-check-report.sarif": SARIF, "dependency-check-report.native.json": {"dependencies": []}, "spotbugs-report.json": SARIF,
                            "semgrep-results.json": {"results": []},
                            "trivy-report.json": {"Results": [{"Packages": [{"Name": "a"}]}]} if trivy else {"Results": []},
                            "conftest-report.json": [{"successes": 0}]}.items():
            (directory / name).write_text(json.dumps(value))

    def test_overlay_preserves_dependencies_and_removes_literal_key(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)
            source.joinpath("pom.xml").write_text((Path("pom.xml").read_text()
                .replace("<configuration>", "<configuration><nvdApiKey>legacy-secret</nvdApiKey>", 1)))
            source.joinpath("src").mkdir()
            source.joinpath("src", "A.java").write_text("class A {}")
            result = baseline.scan_pom(source).read_text()
            self.assertIn("spring-boot-starter-web", result)
            self.assertIn("${env.NVD_API_KEY}", result)
            self.assertNotIn("legacy-secret", result)
            self.assertTrue(source.joinpath("src", "A.java").exists())
            self.assertIn("11.1.1", result); self.assertIn("4.8.6.2", result)
            self.assertIn("<format>XML</format>", result)
            self.assertIn("<ossindexAnalyzerEnabled>false</ossindexAnalyzerEnabled>", result)
            self.assertEqual(2, result.count("<failOnError>true</failOnError>"))

    @mock.patch("security_baseline.subprocess.run")
    def test_docker_digest_is_subprocess_mocked(self, command):
        command.side_effect = [mock.Mock(stdout=""), mock.Mock(stdout="repo@sha256:abc\n")]
        self.assertEqual("repo@sha256:abc", baseline.docker_digest("repo:1"))
        self.assertEqual((("docker", "pull", "repo:1"),), command.call_args_list[0].args)

    @mock.patch("security_baseline.run")
    def test_scan_uses_rootfs_jar_scope(self, command):
        command.return_value = mock.Mock(returncode=0, stdout=json.dumps([{"successes": 0}]))
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict("os.environ", {"NVD_API_KEY": "test"}):
            root = Path(temp); source = root / "source"; controls = root / "controls"; output = root / "out"
            source.mkdir(); controls.mkdir(); output.mkdir()
            baseline.scan(source, output, controls)
        commands = [call.args for call in command.call_args_list]
        self.assertTrue(any("rootfs" in args and "--pkg-types" in args and "library" in args for args in commands))

    def test_valid_zero_findings_are_not_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            self.reports(Path(temp))
            counts = baseline.validate(temp)
            self.assertEqual(0, counts["dependency-check"])
            self.assertEqual(0, counts["conftest"])

    def test_missing_bad_and_empty_inventory_are_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp); self.reports(path, trivy=False)
            with self.assertRaisesRegex(ValueError, "inventory"): baseline.validate(path)
            path.joinpath("trivy-report.json").unlink()
            with self.assertRaisesRegex(ValueError, "missing reports"): baseline.validate(path)

    def test_malformed_native_formats_are_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp); self.reports(path)
            path.joinpath("dependency-check-report.sarif").write_text(json.dumps({"version": "2.0.0", "runs": []}))
            with self.assertRaisesRegex(ValueError, "SARIF"): baseline.validate(path)
            self.reports(path)
            path.joinpath("semgrep-results.json").write_text(json.dumps({"results": [], "errors": ["fatal"]}))
            with self.assertRaisesRegex(ValueError, "Semgrep"): baseline.validate(path)
            self.reports(path)
            path.joinpath("conftest-report.json").write_text("[]")
            with self.assertRaisesRegex(ValueError, "Conftest"): baseline.validate(path)
            self.reports(path)
            path.joinpath("conftest-report.json").write_text(json.dumps([{"successes": True}]))
            with self.assertRaisesRegex(ValueError, "integer"): baseline.validate(path)

    def test_validate_cli_and_native_inventory_requirement(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp); self.reports(path)
            baseline.main(["validate", str(path)])
            path.joinpath("dependency-check-report.native.json").unlink()
            with self.assertRaisesRegex(ValueError, "dependency inventory"):
                baseline.main(["validate", str(path)])

    def test_expected_findings_differ_from_fatal_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp); self.reports(path)
            path.joinpath("semgrep-results.json").write_text(json.dumps({"results": [{"check_id": "x"}]}))
            self.assertEqual(1, baseline.validate(path)["semgrep"])
            path.joinpath("conftest-report.json").write_text(json.dumps([{"successes": "zero"}]))
            with self.assertRaisesRegex(ValueError, "integer"): baseline.validate(path)

if __name__ == "__main__": unittest.main()
