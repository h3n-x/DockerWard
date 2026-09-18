"""Rule WARD-003: Ensure the Docker daemon socket is not mounted into containers."""

from dockerward.collector.models import ContainerTelemetry
from dockerward.rules.base import BaseRule
from dockerward.rules.models import Finding, Severity


class DockerSocketRule(BaseRule):
    """CIS Docker 5.31: Ensure that the Docker socket is not mounted inside containers."""

    rule_id = "WARD-003"
    benchmark_ref = "CIS Docker Benchmark v1.6.0 - 5.31"
    title = "Docker daemon socket mounted into container"
    default_severity = Severity.CRITICAL
    description = "Detects whether /var/run/docker.sock is bound into the container, distinguishing rw vs ro modes."

    def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
        findings: list[Finding] = []

        for mount in telemetry.mounts:
            if not mount.is_docker_socket:
                continue

            # Dynamic severity assignment based on mount access mode
            is_rw = mount.rw or "rw" in mount.mode.lower()
            severity = Severity.CRITICAL if is_rw else Severity.HIGH

            if is_rw:
                description = (
                    f"Container '{telemetry.identity.name}' mounts the Docker daemon socket "
                    f"with READ-WRITE access ({mount.source} -> {mount.destination})."
                )
                impact = (
                    "Read-write access to /var/run/docker.sock grants complete control over the host Docker daemon. "
                    "An attacker inside the container can command the daemon to spawn new containers with "
                    "'-v /:/host --privileged', achieving immediate, full root takeover of the underlying Linux host."
                )
                remediation = (
                    "Remove the '/var/run/docker.sock' bind mount entirely. If container management or metrics "
                    "are necessary, deploy an external daemon agent on the host or use an authorization proxy "
                    "(e.g. docker-socket-proxy) that strictly denies container creation and execution endpoints."
                )
            else:
                description = (
                    f"Container '{telemetry.identity.name}' mounts the Docker daemon socket "
                    f"with READ-ONLY access ({mount.source} -> {mount.destination})."
                )
                impact = (
                    "While read-only mount prevents direct container creation commands on some configurations, "
                    "read access allows querying the Docker Engine API (e.g. GET /containers/{id}/json). "
                    "This leaks all environment variables, private keys, database passwords, and runtime tokens "
                    "from ALL containers co-located on the same host."
                )
                remediation = (
                    "Remove the read-only '/var/run/docker.sock' mount. Gather telemetry and metrics using "
                    "host-level exporters or dedicated Prometheus collectors rather than binding the socket."
                )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    benchmark_ref=self.benchmark_ref,
                    title=f"{self.title} ({'Read-Write' if is_rw else 'Read-Only'})",
                    severity=severity,
                    container_id=telemetry.identity.short_id,
                    container_name=telemetry.identity.name,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    references=[
                        "CIS Docker Benchmark v1.6.0 (Rule 5.31)",
                        "MITRE ATT&CK T1611: Escape to Host via Docker Socket",
                        "CWE-269: Improper Privilege Management",
                    ],
                )
            )

        return findings
