"""Rule WARD-001: Ensure that container executes as non-root user."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity


class RootUserRule(BaseRule):
    """CIS Docker 4.1: Ensure that a user for the container has been created."""

    rule_id = "WARD-001"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 4.1"
    title = "Container running as root (UID 0)"
    default_severity = Severity.HIGH
    description = "Inspects whether the container process executes with root (UID 0) privileges."

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        if not telemetry.security.is_root:
            return []

        current_user = telemetry.security.user or "default root (empty)"

        return [
            Finding(
                rule_id=self.rule_id,
                benchmark_ref=self.benchmark_ref,
                title=self.title,
                severity=self.default_severity,
                container_id=telemetry.identity.short_id,
                container_name=telemetry.identity.name,
                description=(
                    f"Container '{telemetry.identity.name}' executes as root UID 0 "
                    f"(configured user: '{current_user}')."
                ),
                impact=(
                    "Processes executing as UID 0 in an unmapped user namespace share the host "
                    "kernel's root UID. In the event of a container breakout or application flaw, "
                    "the attacker immediately inherits root privileges on the host operating system."
                ),
                remediation=(
                    "Declare a dedicated non-root user in your Dockerfile (e.g. 'USER 1000:1000'), "
                    "or pass '--user 1000:1000' during 'docker run' / 'user: \"1000:1000\"' in Compose."
                ),
                references=[
                    "CIS Docker Benchmark v1.6.0 (Rule 4.1)",
                    "CWE-250: Execution with Unnecessary Privileges",
                ],
            )
        ]
