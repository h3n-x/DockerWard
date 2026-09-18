"""Rule WARD-004: Ensure resource constraints (memory, CPU, PIDs) are enforced in cgroups."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity


class ResourceLimitsRule(BaseRule):
    """CIS Docker 5.10, 5.11, 5.28: Ensure memory, CPU, and PIDs limits are configured."""

    rule_id = "WARD-004"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 5.10, 5.11, 5.28"
    title = "Unconstrained cgroup resource limits"
    default_severity = Severity.MEDIUM
    description = "Checks for missing memory, CPU quota, and PIDs limit constraints in cgroups."

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        findings: list[Finding] = []
        res = telemetry.resources

        # 1. Check Memory Constraint (CIS 5.10)
        if not res.has_memory_limit:
            findings.append(
                Finding(
                    rule_id="WARD-004A",
                    benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.10",
                    title="Missing memory resource constraint",
                    severity=Severity.MEDIUM,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=f"Container '{telemetry.identity.name}' has no cgroup memory ceiling (Memory=0 bytes).",
                    impact=(
                        "A memory leak or denial-of-service payload inside this container can exhaust all "
                        "available host RAM and swap space, triggering the Linux kernel Out-Of-Memory (OOM) killer "
                        "which may terminate critical system processes or neighboring workloads."
                    ),
                    remediation=(
                        "Define a hard memory ceiling using '--memory=512m' (or expected quota) in 'docker run' "
                        "or 'mem_limit: 512m' in docker-compose.yml."
                    ),
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.10)",
                        "CWE-400: Uncontrolled Resource Consumption",
                    ],
                )
            )

        # 2. Check CPU Constraint (CIS 5.11)
        if not res.has_cpu_limit:
            findings.append(
                Finding(
                    rule_id="WARD-004B",
                    benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.11",
                    title="Missing CPU bandwidth constraint",
                    severity=Severity.MEDIUM,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=f"Container '{telemetry.identity.name}' has no CFS CPU limit enforced (NanoCPUs=0).",
                    impact=(
                        "A runaway compute loop inside this container can starve the host CPU cores, "
                        "increasing system load averages and severely degrading the latency of all other "
                        "services running on the host."
                    ),
                    remediation=(
                        "Configure CFS CPU quota using '--cpus=1.0' (or appropriate fraction) in 'docker run' "
                        "or 'cpus: 1.0' in docker-compose.yml."
                    ),
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.11)",
                        "CWE-400: Uncontrolled Resource Consumption",
                    ],
                )
            )

        # 3. Check PIDs Constraint (CIS 5.28)
        if not res.has_pids_limit:
            findings.append(
                Finding(
                    rule_id="WARD-004C",
                    benchmark_ref="CIS Docker Benchmark v1.6.0 - 5.28",
                    title="Missing PIDs limit constraint (fork-bomb risk)",
                    severity=Severity.MEDIUM,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=f"Container '{telemetry.identity.name}' has no cgroups pids_limit ceiling configured.",
                    impact=(
                        "Without a process count ceiling, a compromised container can launch a fork bomb, "
                        "rapidly exhausting the host Linux kernel's global PID table (/proc/sys/kernel/pid_max) "
                        "and rendering the host operating system unresponsive."
                    ),
                    remediation=(
                        "Restrict process count by adding '--pids-limit=100' (or appropriate maximum) in 'docker run' "
                        "or 'pids_limit: 100' in docker-compose.yml."
                    ),
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.28)",
                        "CWE-400: Uncontrolled Resource Consumption",
                    ],
                )
            )

        return findings
