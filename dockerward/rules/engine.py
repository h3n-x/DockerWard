"""Policy engine executing container runtime security audits."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.definitions import ALL_RULES
from dockerward.rules.models import Finding, Severity

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class PolicyEngine:
    """Orchestrates security rule evaluation across inspected containers."""

    def __init__(self, rules: list[BaseRule] | None = None) -> None:
        """Initialize the policy engine with a set of security rules.

        Args:
            rules: Optional list of rules to evaluate. Defaults to ALL_RULES.
        """
        self._rules: list[BaseRule] = rules if rules is not None else list(ALL_RULES)

    @property
    def rules(self) -> list[BaseRule]:
        """Return the active rule instances registered in the engine."""
        return self._rules

    def audit_container(self, telemetry: ContainerTelemetry) -> list[Finding]:
        """Audit a single container snapshot against all active security rules.

        Args:
            telemetry: Audited runtime telemetry of a container.

        Returns:
            list[Finding]: All detected security violations sorted by severity (highest first).
        """
        findings: list[Finding] = []
        for rule in self._rules:
            try:
                rule_findings = rule.evaluate(telemetry)
                findings.extend(rule_findings)
            except Exception as exc:
                # Capture evaluation failures gracefully without crashing other audits
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        benchmark_ref=rule.benchmark_ref,
                        title=f"Rule evaluation error: {rule.title}",
                        severity=Severity.INFO,
                        container_id=telemetry.identity.short_id,
                        container_name=telemetry.identity.name,
                        description=f"Rule {rule.rule_id} raised an unhandled exception: {exc}",
                        impact="Auditor was unable to evaluate this specific security check.",
                        remediation="Inspect container configuration and report this error.",
                    )
                )

        return self.sort_findings(findings)

    def audit_containers(self, containers: list[ContainerTelemetry]) -> list[Finding]:
        """Audit multiple container snapshots and collect aggregated findings.

        Args:
            containers: List of container telemetry snapshots.

        Returns:
            list[Finding]: All detected security violations sorted by severity.
        """
        all_findings: list[Finding] = []
        for container in containers:
            all_findings.extend(self.audit_container(container))
        return self.sort_findings(all_findings)

    @staticmethod
    def sort_findings(findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity descending (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)."""
        return sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
            reverse=True,
        )

    @staticmethod
    def filter_by_min_severity(findings: list[Finding], min_severity: Severity) -> list[Finding]:
        """Filter a list of findings to only include those at or above a minimum severity.

        Args:
            findings: List of findings to filter.
            min_severity: Minimum severity threshold.

        Returns:
            list[Finding]: Filtered findings meeting or exceeding threshold.
        """
        threshold = SEVERITY_ORDER.get(min_severity, 0)
        return [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]

    @staticmethod
    def get_summary(findings: list[Finding]) -> dict[Severity, int]:
        """Calculate counts of findings grouped by severity.

        Args:
            findings: List of findings.

        Returns:
            dict[Severity, int]: Map of severity level to count of occurrences.
        """
        counts = {sev: 0 for sev in Severity}
        for finding in findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts
