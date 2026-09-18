"""Unit tests for OASIS SARIF v2.1.0 exporter."""

import json
import pytest

from dockerward.reporting.sarif import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    SEVERITY_TO_SARIF_LEVEL,
    SEVERITY_TO_SECURITY_SCORE,
    SarifExporter,
)
from dockerward.rules.models import Finding, Severity


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Sample findings covering various severities and rule codes."""
    return [
        Finding(
            rule_id="WARD-002",
            benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.4",
            title="Container running in privileged mode",
            severity=Severity.CRITICAL,
            container_id="1234567890ab",
            container_name="victim-box",
            description="Container 'victim-box' runs with Privileged=True.",
            impact="Lifts all kernel cgroups and isolation.",
            remediation="Remove privileged: true.",
            references=["CIS Docker Benchmark v1.6.0 (Rule 5.4)"],
        ),
        Finding(
            rule_id="WARD-001",
            benchmark_ref="CIS Docker Benchmark v1.6.0 - 4.1",
            title="Container running as root (UID 0)",
            severity=Severity.HIGH,
            container_id="1234567890ab",
            container_name="victim-box",
            description="Container 'victim-box' executes as root UID 0.",
            impact="Inherits root privileges on host.",
            remediation="Use USER 1000:1000.",
            references=["CIS Docker Benchmark v1.6.0 (Rule 4.1)"],
        ),
        Finding(
            rule_id="WARD-004A",
            benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.10",
            title="Missing memory resource constraint",
            severity=Severity.MEDIUM,
            container_id="1234567890ab",
            container_name="victim-box",
            description="Container 'victim-box' has no cgroup memory ceiling.",
            impact="Risks OOM killer terminating processes.",
            remediation="Add --memory=512m.",
            references=["CIS Docker Benchmark v1.6.0 (Rule 5.10)"],
        ),
        Finding(
            rule_id="WARD-005B",
            benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.3",
            title="Baseline capabilities not dropped",
            severity=Severity.LOW,
            container_id="1234567890ab",
            container_name="victim-box",
            description="Container 'victim-box' does not drop all capabilities.",
            impact="Retains unnecessary default capabilities.",
            remediation="Apply --cap-drop=ALL.",
            references=["CIS Docker Benchmark v1.6.0 (Rule 5.3)"],
        ),
    ]


class TestSarifExporter:
    """Tests for SarifExporter schema compliance and data fidelity."""

    def test_empty_findings_structure(self) -> None:
        sarif = SarifExporter.generate([])
        assert sarif["$schema"] == SARIF_SCHEMA_URI
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "DockerWard"
        assert len(run["tool"]["driver"]["rules"]) > 0
        assert run["results"] == []

    def test_sarif_results_and_rule_mapping(self, sample_findings: list[Finding]) -> None:
        sarif = SarifExporter.generate(sample_findings)
        run = sarif["runs"][0]
        results = run["results"]

        assert len(results) == 4

        # Verify level mappings
        levels = [r["level"] for r in results]
        assert levels == ["error", "error", "warning", "note"]

        # Check first finding details
        first_result = results[0]
        assert first_result["ruleId"] == "WARD-002"
        assert first_result["level"] == "error"
        assert "Privileged=True" in first_result["message"]["text"]

        # Verify physical location
        loc = first_result["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "containers/victim-box"
        assert loc["physicalLocation"]["region"]["startLine"] == 1
        assert loc["logicalLocations"][0]["name"] == "victim-box"
        assert loc["logicalLocations"][0]["kind"] == "container"

        # Verify custom properties
        props = first_result["properties"]
        assert props["containerId"] == "1234567890ab"
        assert props["containerName"] == "victim-box"
        assert props["severity"] == "CRITICAL"
        assert props["remediation"] == "Remove privileged: true."

    def test_driver_rules_contain_markdown_help_and_scores(self, sample_findings: list[Finding]) -> None:
        sarif = SarifExporter.generate(sample_findings)
        driver_rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_map = {r["id"]: r for r in driver_rules}

        assert "WARD-002" in rule_map
        r2 = rule_map["WARD-002"]
        assert "markdown" in r2["help"]
        assert "### Remediation" in r2["help"]["markdown"]
        assert "### Impact" in r2["help"]["markdown"]
        assert r2["properties"]["security-severity"] == "9.8"
        assert r2["properties"]["precision"] == "very-high"

        assert "WARD-004A" in rule_map
        r4 = rule_map["WARD-004A"]
        assert r4["properties"]["security-severity"] == "5.5"

    def test_to_json_validity(self, sample_findings: list[Finding]) -> None:
        raw_json = SarifExporter.to_json(sample_findings)
        parsed = json.loads(raw_json)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == 4
