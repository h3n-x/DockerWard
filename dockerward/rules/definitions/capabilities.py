"""Rule WARD-005: Ensure Linux capabilities are restricted and dangerous capabilities avoided."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity

DANGEROUS_CAPABILITIES: dict[str, str] = {
    "SYS_ADMIN": "Allows filesystem mounting, cgroup configuration, and potential host container breakout.",
    "CAP_SYS_ADMIN": "Allows filesystem mounting, cgroup configuration, and potential host container breakout.",
    "NET_ADMIN": "Allows modifying routing tables, firewall rules, and sniffing raw network traffic.",
    "CAP_NET_ADMIN": "Allows modifying routing tables, firewall rules, and sniffing raw network traffic.",
    "SYS_PTRACE": "Enables ptrace debugging of processes, enabling memory injection and privilege escalation.",
    "CAP_SYS_PTRACE": "Enables ptrace debugging of processes, enabling memory injection and privilege escalation.",
    "DAC_OVERRIDE": "Bypasses all filesystem read, write, and execute permission checks.",
    "CAP_DAC_OVERRIDE": "Bypasses all filesystem read, write, and execute permission checks.",
    "SYS_MODULE": "Allows loading and unloading arbitrary Linux kernel modules on the host kernel.",
    "CAP_SYS_MODULE": "Allows loading and unloading arbitrary Linux kernel modules on the host kernel.",
    "SYS_RAWIO": "Permits raw I/O port operations on host hardware.",
    "CAP_SYS_RAWIO": "Permits raw I/O port operations on host hardware.",
}


class CapabilitiesRule(BaseRule):
    """CIS Docker 5.3: Ensure Linux capabilities are restricted and dangerous capabilities not granted."""

    rule_id = "WARD-005"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 5.3"
    title = "Insecure Linux capabilities configuration"
    default_severity = Severity.HIGH
    description = "Inspects for granted high-risk kernel capabilities and checks if --cap-drop=ALL is applied."

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        findings: list[Finding] = []
        caps = telemetry.capabilities

        # 1. Check for Dangerous Capabilities explicitly added
        detected_dangerous: list[tuple[str, str]] = []
        for cap in caps.cap_add:
            normalized = cap.upper().replace("CAP_", "")
            with_prefix = f"CAP_{normalized}"
            if normalized in DANGEROUS_CAPABILITIES or with_prefix in DANGEROUS_CAPABILITIES:
                explanation = DANGEROUS_CAPABILITIES.get(normalized) or DANGEROUS_CAPABILITIES.get(with_prefix, "")
                detected_dangerous.append((with_prefix, explanation))

        if detected_dangerous:
            cap_names = ", ".join(name for name, _ in detected_dangerous)
            explanations = " ".join(f"[{name}: {exp}]" for name, exp in detected_dangerous)
            findings.append(
                Finding(
                    rule_id="WARD-005A",
                    benchmark_ref=self.benchmark_ref,
                    title="Dangerous Linux kernel capabilities granted",
                    severity=Severity.HIGH,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=f"Container '{telemetry.identity.name}' explicitly added dangerous capabilities: {cap_names}.",
                    impact=(
                        f"Granting high-privilege kernel capabilities weakens the container isolation boundary. {explanations}"
                    ),
                    remediation=(
                        f"Remove high-risk capabilities ({cap_names}) from '--cap-add' or Compose 'cap_add'. "
                        "Re-evaluate application requirements to operate with restricted privileges."
                    ),
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.3)",
                        "Linux Capabilities Man Page: capabilities(7)",
                    ],
                )
            )

        # 2. Check if default capabilities are dropped (CIS recommendation: drop ALL)
        if not caps.drops_all:
            findings.append(
                Finding(
                    rule_id="WARD-005B",
                    benchmark_ref=self.benchmark_ref,
                    title="Baseline capabilities not dropped (--cap-drop=ALL missing)",
                    severity=Severity.LOW,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=f"Container '{telemetry.identity.name}' does not drop all default capabilities.",
                    impact=(
                        "By default, Docker retains ~14 capabilities (such as CAP_NET_RAW, CAP_CHOWN). "
                        "Applying the principle of least privilege requires dropping all capabilities and only "
                        "selectively adding the exact subset required."
                    ),
                    remediation=(
                        "Apply '--cap-drop=ALL' in 'docker run' or 'cap_drop: [ALL]' in docker-compose.yml, "
                        "then explicitly re-add only strictly necessary capabilities via '--cap-add'."
                    ),
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.3)",
                        "Docker Security Guidelines: Restricting Capabilities",
                    ],
                )
            )

        return findings
