"""Rule WARD-002: Ensure privileged containers are not used."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity


class PrivilegedModeRule(BaseRule):
    """CIS Docker 5.4: Ensure privileged containers are not used."""

    rule_id = "WARD-002"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 5.4"
    title = "Container running in privileged mode"
    default_severity = Severity.CRITICAL
    description = "Detects whether the container was spawned with the --privileged flag."

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        if not telemetry.security.privileged:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                benchmark_ref=self.benchmark_ref,
                title=self.title,
                severity=self.default_severity,
                container_id=telemetry.identity.short_id,
                container_name=telemetry.identity.name,
                description=(
                    f"Container '{telemetry.identity.name}' runs with HostConfig.Privileged=True."
                ),
                impact=(
                    "Running with --privileged gives all Linux kernel capabilities to the container "
                    "and lifts all device cgroup limitations. The container can access all host /dev "
                    "devices, modify host kernel settings, and trivially escape container isolation."
                ),
                remediation=(
                    "Remove the 'privileged: true' configuration from docker-compose or omit '--privileged' "
                    "from 'docker run'. If specific hardware access is required, grant only the specific "
                    "device with '--device' and minimal capabilities with '--cap-add'."
                ),
                references=[
                    "CIS Docker Benchmark v1.6.0 (Rule 5.4)",
                    "MITRE ATT&CK T1611: Escape to Host",
                ],
            )
        ]
