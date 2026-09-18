"""Rule WARD-006: Ensure default seccomp profile is not disabled."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity


class SeccompRule(BaseRule):
    """CIS Docker 5.21: Ensure default seccomp profile is not disabled."""

    rule_id = "WARD-006"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 5.21"
    title = "Default seccomp profile disabled (unconfined)"
    default_severity = Severity.HIGH
    description = (
        "Detects whether the container disables the default Docker seccomp "
        "syscall filter via security_opt unconfined."
    )

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        if not telemetry.security.seccomp_unconfined:
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
                    f"Container '{telemetry.identity.name}' runs with seccomp profile disabled "
                    f"('seccomp:unconfined' in security_opt)."
                ),
                impact=(
                    "Disabling seccomp unblocks more than 300 Linux system calls (such as keyctl, "
                    "process_vm_readv, reboot, acct) that are otherwise filtered by Docker's default "
                    "security profile. This significantly broadens the attack surface for Linux kernel "
                    "privilege escalation and container breakout exploits."
                ),
                remediation=(
                    "Remove 'seccomp:unconfined' or 'seccomp=unconfined' from container configuration, "
                    "or provide a restrictive custom seccomp profile with "
                    "'--security-opt seccomp=/path/to/profile.json'."
                ),
                references=[
                    "CIS Docker Benchmark v1.6.0 (Rule 5.21)",
                    "MITRE ATT&CK T1611: Escape to Host",
                    "Docker Security Guidelines: Seccomp security profiles",
                ],
            )
        ]
