"""SARIF (Static Analysis Results Interchange Format) 2.1.0 exporter for DockerWard.

Conforms to OASIS SARIF v2.1.0 and GitHub Code Scanning specifications.
"""

from typing import Any
import json

from dockerward import __version__
from dockerward.rules.models import Finding, Severity

# OASIS SARIF specification schema URI
SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

# Severity mappings to SARIF 2.1.0 levels
SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# CVSS-aligned security severity score string (used by GitHub Code Scanning)
SEVERITY_TO_SECURITY_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.8",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}

KNOWN_RULES_METADATA: dict[str, dict[str, Any]] = {
    "WARD-001": {
        "name": "ContainerRootUserExecution",
        "shortDescription": "Container running as root (UID 0)",
        "fullDescription": (
            "Inspects whether the container process executes with root (UID 0) privileges. "
            "Processes running as UID 0 share the host kernel's root UID unless user namespace remapping is enabled."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 4.1",
        "severity": Severity.HIGH,
    },
    "WARD-002": {
        "name": "ContainerPrivilegedMode",
        "shortDescription": "Container running in privileged mode",
        "fullDescription": (
            "Detects whether the container runs with the --privileged flag, lifting all device cgroup limitations "
            "and granting all Linux kernel capabilities to the container."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.4",
        "severity": Severity.CRITICAL,
    },
    "WARD-003": {
        "name": "DockerSocketMounted",
        "shortDescription": "Docker daemon socket mounted into container",
        "fullDescription": (
            "Detects whether /var/run/docker.sock is bind-mounted into the container. "
            "Read-write access allows complete host takeover; read-only access leaks secrets and environment variables."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.31",
        "severity": Severity.CRITICAL,
    },
    "WARD-004A": {
        "name": "MissingMemoryConstraint",
        "shortDescription": "Missing memory resource constraint",
        "fullDescription": (
            "Checks for unconstrained cgroup memory limits. An uncontrolled memory spike can exhaust host RAM "
            "and trigger the Linux kernel Out-Of-Memory (OOM) killer."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.10",
        "severity": Severity.MEDIUM,
    },
    "WARD-004B": {
        "name": "MissingCpuBandwidthConstraint",
        "shortDescription": "Missing CPU bandwidth constraint",
        "fullDescription": (
            "Checks for unconstrained CFS CPU quota. Runaway compute loops can starve host CPU cores "
            "and degrade neighboring services."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.11",
        "severity": Severity.MEDIUM,
    },
    "WARD-004C": {
        "name": "MissingPidsLimitConstraint",
        "shortDescription": "Missing PIDs limit constraint (fork-bomb risk)",
        "fullDescription": (
            "Checks for unconstrained process count ceiling in cgroups. Compromised processes can trigger a fork-bomb, "
            "exhausting the host kernel PID table (/proc/sys/kernel/pid_max)."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.28",
        "severity": Severity.MEDIUM,
    },
    "WARD-005A": {
        "name": "DangerousCapabilitiesGranted",
        "shortDescription": "Dangerous Linux kernel capabilities granted",
        "fullDescription": (
            "Detects high-privilege kernel capabilities explicitly added (such as SYS_ADMIN, NET_ADMIN, or SYS_PTRACE) "
            "that breach container isolation boundaries."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.3",
        "severity": Severity.HIGH,
    },
    "WARD-005B": {
        "name": "BaselineCapabilitiesNotDropped",
        "shortDescription": "Baseline capabilities not dropped (--cap-drop=ALL missing)",
        "fullDescription": (
            "Inspects whether default Docker capabilities were dropped following the principle of least privilege."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.3",
        "severity": Severity.LOW,
    },
    "WARD-006": {
        "name": "DefaultSeccompProfileDisabled",
        "shortDescription": "Default seccomp profile disabled (unconfined)",
        "fullDescription": (
            "Detects whether the default Docker seccomp syscall filter is disabled via security_opt unconfined, "
            "exposing 300+ Linux system calls to the container."
        ),
        "benchmark": "CIS Docker Benchmark v1.6.0 - 5.21",
        "severity": Severity.HIGH,
    },
}


class SarifExporter:
    """Converts DockerWard security findings into an OASIS SARIF v2.1.0 report."""

    @classmethod
    def generate(cls, findings: list[Finding]) -> dict[str, Any]:
        """Generate a SARIF 2.1.0 document dictionary from a list of security findings.

        Args:
            findings: Detected runtime security policy violations.

        Returns:
            dict[str, Any]: OASIS SARIF 2.1.0 compatible document.
        """
        rules_map: dict[str, dict[str, Any]] = {}
        results_list: list[dict[str, Any]] = []

        # 1. Build results and dynamic rule definitions from findings
        for finding in findings:
            rule_id = finding.rule_id
            level = SEVERITY_TO_SARIF_LEVEL.get(finding.severity, "warning")
            sec_score = SEVERITY_TO_SECURITY_SCORE.get(finding.severity, "5.0")

            if rule_id not in rules_map:
                meta = KNOWN_RULES_METADATA.get(rule_id, {})
                rule_name = meta.get("name", rule_id.replace("-", "_"))
                short_desc = meta.get("shortDescription", finding.title)
                full_desc = meta.get("fullDescription", finding.title)
                benchmark = meta.get("benchmark", finding.benchmark_ref)

                help_markdown = (
                    f"### Remediation\n{finding.remediation}\n\n"
                    f"### Impact\n{finding.impact}\n\n"
                    f"**Benchmark Reference:** {benchmark}"
                )
                if finding.references:
                    help_markdown += "\n\n**References:**\n" + "\n".join(f"- {ref}" for ref in finding.references)

                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": rule_name,
                    "shortDescription": {"text": short_desc},
                    "fullDescription": {"text": full_desc},
                    "helpUri": "https://github.com/h3n-x/DockerWard#cis-docker-benchmark-rules",
                    "help": {
                        "text": f"Remediation:\n{finding.remediation}\n\nImpact:\n{finding.impact}\n\nBenchmark: {benchmark}",
                        "markdown": help_markdown,
                    },
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "precision": "very-high",
                        "security-severity": sec_score,
                        "tags": [
                            "security",
                            "containers",
                            "docker",
                            "runtime",
                            "cis-benchmark",
                        ],
                    },
                }

            # Result object for this finding
            result_entry: dict[str, Any] = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"containers/{finding.container_name}",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                            },
                        },
                        "logicalLocations": [
                            {
                                "name": finding.container_name,
                                "fullyQualifiedName": f"docker://{finding.container_name} ({finding.container_id})",
                                "kind": "container",
                            }
                        ],
                    }
                ],
                "properties": {
                    "containerId": finding.container_id,
                    "containerName": finding.container_name,
                    "severity": finding.severity.value,
                    "benchmark": finding.benchmark_ref,
                    "impact": finding.impact,
                    "remediation": finding.remediation,
                },
            }
            results_list.append(result_entry)

        # 2. Also register any known rules that didn't trigger, so tool driver rules list is complete
        for rule_id, meta in KNOWN_RULES_METADATA.items():
            if rule_id not in rules_map:
                default_sev = meta["severity"]
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": meta["name"],
                    "shortDescription": {"text": meta["shortDescription"]},
                    "fullDescription": {"text": meta["fullDescription"]},
                    "helpUri": "https://github.com/h3n-x/DockerWard#cis-docker-benchmark-rules",
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(default_sev, "warning")
                    },
                    "properties": {
                        "precision": "very-high",
                        "security-severity": SEVERITY_TO_SECURITY_SCORE.get(default_sev, "5.0"),
                        "tags": [
                            "security",
                            "containers",
                            "docker",
                            "runtime",
                            "cis-benchmark",
                        ],
                    },
                }

        # Sorted rules list for deterministic output
        sorted_rules = [rules_map[k] for k in sorted(rules_map.keys())]

        return {
            "$schema": SARIF_SCHEMA_URI,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DockerWard",
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": "https://github.com/h3n-x/DockerWard",
                            "rules": sorted_rules,
                        }
                    },
                    "results": results_list,
                }
            ],
        }

    @classmethod
    def to_json(cls, findings: list[Finding], indent: int = 2) -> str:
        """Serialize findings into formatted SARIF JSON string."""
        data = cls.generate(findings)
        return json.dumps(data, indent=indent)
