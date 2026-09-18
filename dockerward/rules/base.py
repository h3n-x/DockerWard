"""Abstract base rule class for DockerWard policy inspection."""

from abc import ABC, abstractmethod
from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.models import Finding, Severity


class BaseRule(ABC):
    """Abstract base class for all Docker runtime security rules."""

    rule_id: str
    benchmark_ref: str
    title: str
    default_severity: Severity
    description: str

    @abstractmethod
    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        """Audit a container telemetry snapshot against this rule.

        Args:
            telemetry: Audited runtime state of the container.

        Returns:
            list[Finding]: List of findings detected by this rule (empty if compliant).
        """
        ...
