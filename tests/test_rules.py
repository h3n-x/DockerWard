"""Unit tests for DockerWard security rules and policy engine."""

from typing import Any
import pytest

from dockerward.collector.models import (
    ContainerIdentity,
    ContainerTelemetry,
    ExecutionSecurity,
    LinuxCapabilities,
    MountInspection,
    NetworkExposition,
    ResourceLimits,
)
from dockerward.rules.base import BaseRule
from dockerward.rules.definitions.capabilities import CapabilitiesRule
from dockerward.rules.definitions.docker_socket import DockerSocketRule
from dockerward.rules.definitions.privileged_mode import PrivilegedModeRule
from dockerward.rules.definitions.resource_limits import ResourceLimitsRule
from dockerward.rules.definitions.root_user import RootUserRule
from dockerward.rules.definitions.seccomp import SeccompRule
from dockerward.rules.engine import PolicyEngine
from dockerward.rules.models import Finding, Severity


def create_telemetry_fixture(
    user: str = "1000:1000",
    privileged: bool = False,
    security_opt: list[str] | None = None,
    cap_add: list[str] | None = None,
    cap_drop: list[str] | None = None,
    memory_bytes: int = 536870912,  # 512 MB
    nano_cpus: int = 1000000000,    # 1 CPU
    pids_limit: int | None = 100,
    mounts: list[MountInspection] | None = None,
    container_name: str = "test-container",
) -> ContainerTelemetry:
    """Helper to produce a compliant baseline telemetry snapshot with overrides."""
    return ContainerTelemetry(
        identity=ContainerIdentity(
            id="a" * 64,
            short_id="aaaaaaaaaaaa",
            name=container_name,
            image="test:latest",
            status="running",
            created_at="2026-09-17T12:00:00Z",
        ),
        security=ExecutionSecurity(
            user=user,
            privileged=privileged,
            read_only_rootfs=True,
            security_opt=security_opt or [],
            no_new_privileges=True,
        ),
        capabilities=LinuxCapabilities(
            cap_add=cap_add or [],
            cap_drop=cap_drop if cap_drop is not None else ["ALL"],
        ),
        resources=ResourceLimits(
            memory_bytes=memory_bytes,
            nano_cpus=nano_cpus,
            pids_limit=pids_limit,
        ),
        network=NetworkExposition(
            network_mode="bridge",
            port_bindings=[],
        ),
        mounts=mounts or [],
        labels={},
    )


class TestRootUserRule:
    """Tests for WARD-001 (CIS 4.1): Root user execution."""

    def setup_method(self) -> None:
        self.rule = RootUserRule()

    @pytest.mark.parametrize("user", ["", "0", "root", "ROOT", "0:0", "0:1000"])
    def test_violation_when_root(self, user: str) -> None:
        telemetry = create_telemetry_fixture(user=user)
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-001"
        assert f.severity == Severity.HIGH
        assert "UID 0" in f.description
        assert "CIS Docker Benchmark" in f.benchmark_ref

    @pytest.mark.parametrize("user", ["1000:1000", "appuser", "nobody", "1001"])
    def test_compliant_when_non_root(self, user: str) -> None:
        telemetry = create_telemetry_fixture(user=user)
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestPrivilegedModeRule:
    """Tests for WARD-002 (CIS 5.4): Privileged mode container execution."""

    def setup_method(self) -> None:
        self.rule = PrivilegedModeRule()

    def test_violation_when_privileged(self) -> None:
        telemetry = create_telemetry_fixture(privileged=True)
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-002"
        assert f.severity == Severity.CRITICAL
        assert "Privileged=True" in f.description

    def test_compliant_when_unprivileged(self) -> None:
        telemetry = create_telemetry_fixture(privileged=False)
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestDockerSocketRule:
    """Tests for WARD-003 (CIS 5.31): Docker socket mount."""

    def setup_method(self) -> None:
        self.rule = DockerSocketRule()

    def test_violation_rw_socket_critical(self) -> None:
        mount = MountInspection(
            source="/var/run/docker.sock",
            destination="/var/run/docker.sock",
            mode="rw",
            rw=True,
        )
        telemetry = create_telemetry_fixture(mounts=[mount])
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-003"
        assert f.severity == Severity.CRITICAL
        assert "READ-WRITE" in f.description

    def test_violation_ro_socket_high(self) -> None:
        mount = MountInspection(
            source="/var/run/docker.sock",
            destination="/var/run/docker.sock",
            mode="ro",
            rw=False,
        )
        telemetry = create_telemetry_fixture(mounts=[mount])
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-003"
        assert f.severity == Severity.HIGH
        assert "READ-ONLY" in f.description

    def test_compliant_when_no_docker_socket(self) -> None:
        mount = MountInspection(
            source="/data/storage",
            destination="/app/storage",
            mode="rw",
            rw=True,
        )
        telemetry = create_telemetry_fixture(mounts=[mount])
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestResourceLimitsRule:
    """Tests for WARD-004 (CIS 5.10, 5.11, 5.28): cgroup resource constraints."""

    def setup_method(self) -> None:
        self.rule = ResourceLimitsRule()

    def test_violation_all_unbounded(self) -> None:
        telemetry = create_telemetry_fixture(
            memory_bytes=0,
            nano_cpus=0,
            pids_limit=None,
        )
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 3
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"WARD-004A", "WARD-004B", "WARD-004C"}
        for f in findings:
            assert f.severity == Severity.MEDIUM

    def test_partial_limits_enforced(self) -> None:
        # Only memory configured, CPU and PIDs missing
        telemetry = create_telemetry_fixture(
            memory_bytes=268435456,
            nano_cpus=0,
            pids_limit=None,
        )
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 2
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"WARD-004B", "WARD-004C"}

    def test_compliant_when_all_limits_enforced(self) -> None:
        telemetry = create_telemetry_fixture(
            memory_bytes=268435456,
            nano_cpus=1000000000,
            pids_limit=50,
        )
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestCapabilitiesRule:
    """Tests for WARD-005 (CIS 5.3): Linux kernel capabilities."""

    def setup_method(self) -> None:
        self.rule = CapabilitiesRule()

    def test_violation_dangerous_capabilities_granted(self) -> None:
        telemetry = create_telemetry_fixture(
            cap_add=["SYS_ADMIN", "NET_ADMIN"],
            cap_drop=["ALL"],
        )
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-005A"
        assert f.severity == Severity.HIGH
        assert "CAP_SYS_ADMIN" in f.description
        assert "CAP_NET_ADMIN" in f.description

    def test_violation_missing_cap_drop_all(self) -> None:
        telemetry = create_telemetry_fixture(
            cap_add=[],
            cap_drop=[],  # Did not drop ALL
        )
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-005B"
        assert f.severity == Severity.LOW
        assert "drops_all" not in f.description

    def test_violation_both_dangerous_caps_and_no_drop_all(self) -> None:
        telemetry = create_telemetry_fixture(
            cap_add=["SYS_PTRACE"],
            cap_drop=["CHOWN"],
        )
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 2
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"WARD-005A", "WARD-005B"}

    def test_compliant_dropped_all_and_no_dangerous_caps(self) -> None:
        telemetry = create_telemetry_fixture(
            cap_add=["CHOWN"],  # Safe cap if needed
            cap_drop=["ALL"],
        )
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestSeccompRule:
    """Tests for WARD-006 (CIS 5.21): Seccomp syscall filtering."""

    def setup_method(self) -> None:
        self.rule = SeccompRule()

    @pytest.mark.parametrize("opt", ["seccomp:unconfined", "seccomp=unconfined", "SECCOMP=UNCONFINED"])
    def test_violation_when_unconfined(self, opt: str) -> None:
        telemetry = create_telemetry_fixture(security_opt=[opt])
        findings = self.rule.evaluate(telemetry)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "WARD-006"
        assert f.severity == Severity.HIGH
        assert "seccomp:unconfined" in f.description

    def test_compliant_with_default_seccomp(self) -> None:
        telemetry = create_telemetry_fixture(security_opt=[])
        findings = self.rule.evaluate(telemetry)
        assert findings == []

    def test_compliant_with_other_security_opts(self) -> None:
        telemetry = create_telemetry_fixture(security_opt=["apparmor:docker-default"])
        findings = self.rule.evaluate(telemetry)
        assert findings == []


class TestPolicyEngine:
    """Tests for PolicyEngine orchestration, sorting, and reporting."""

    def test_engine_evaluates_all_registered_rules(self) -> None:
        engine = PolicyEngine()
        assert len(engine.rules) == 6

    def test_fully_hardened_container_has_zero_findings(self) -> None:
        engine = PolicyEngine()
        hardened = create_telemetry_fixture()
        findings = engine.audit_container(hardened)
        assert findings == []

    def test_vulnerable_container_produces_sorted_findings(self) -> None:
        engine = PolicyEngine()
        vulnerable = create_telemetry_fixture(
            user="0",
            privileged=True,
            security_opt=["seccomp:unconfined"],
            cap_add=["SYS_ADMIN"],
            cap_drop=[],
            memory_bytes=0,
            nano_cpus=0,
            pids_limit=None,
            mounts=[
                MountInspection(
                    source="/var/run/docker.sock",
                    destination="/var/run/docker.sock",
                    mode="rw",
                    rw=True,
                )
            ],
        )

        findings = engine.audit_container(vulnerable)
        assert len(findings) > 0

        # Verify sorted by severity: CRITICAL comes first
        severities = [f.severity for f in findings]
        assert severities[0] == Severity.CRITICAL

        # Verify specific expected rule IDs
        detected_ids = {f.rule_id for f in findings}
        assert "WARD-001" in detected_ids  # root
        assert "WARD-002" in detected_ids  # privileged
        assert "WARD-003" in detected_ids  # docker socket rw
        assert "WARD-004A" in detected_ids # memory
        assert "WARD-004B" in detected_ids # cpu
        assert "WARD-004C" in detected_ids # pids
        assert "WARD-005A" in detected_ids # sys_admin
        assert "WARD-005B" in detected_ids # no drop all
        assert "WARD-006" in detected_ids  # seccomp unconfined

    def test_audit_multiple_containers(self) -> None:
        engine = PolicyEngine()
        c1 = create_telemetry_fixture(container_name="c1", privileged=True)
        c2 = create_telemetry_fixture(container_name="c2", user="0")
        c3 = create_telemetry_fixture(container_name="c3")  # Hardened

        findings = engine.audit_containers([c1, c2, c3])
        names = {f.container_name for f in findings}
        assert "c1" in names
        assert "c2" in names
        assert "c3" not in names

    def test_filter_by_min_severity(self) -> None:
        engine = PolicyEngine()
        findings = [
            Finding(
                rule_id="WARD-002",
                benchmark_ref="CIS 5.4",
                title="Privileged",
                severity=Severity.CRITICAL,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                rule_id="WARD-001",
                benchmark_ref="CIS 4.1",
                title="Root",
                severity=Severity.HIGH,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                rule_id="WARD-004A",
                benchmark_ref="CIS 5.10",
                title="Memory",
                severity=Severity.MEDIUM,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                rule_id="WARD-005B",
                benchmark_ref="CIS 5.3",
                title="Drop all",
                severity=Severity.LOW,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
        ]

        high_and_above = engine.filter_by_min_severity(findings, Severity.HIGH)
        assert len(high_and_above) == 2
        assert {f.severity for f in high_and_above} == {Severity.CRITICAL, Severity.HIGH}

        critical_only = engine.filter_by_min_severity(findings, Severity.CRITICAL)
        assert len(critical_only) == 1
        assert critical_only[0].severity == Severity.CRITICAL

    def test_summary_calculation(self) -> None:
        findings = [
            Finding(
                rule_id="WARD-002",
                benchmark_ref="CIS 5.4",
                title="Privileged",
                severity=Severity.CRITICAL,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                rule_id="WARD-001",
                benchmark_ref="CIS 4.1",
                title="Root",
                severity=Severity.HIGH,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
            Finding(
                rule_id="WARD-006",
                benchmark_ref="CIS 5.21",
                title="Seccomp",
                severity=Severity.HIGH,
                container_id="c1",
                container_name="c1",
                description="desc",
                impact="impact",
                remediation="rem",
            ),
        ]

        summary = PolicyEngine.get_summary(findings)
        assert summary[Severity.CRITICAL] == 1
        assert summary[Severity.HIGH] == 2
        assert summary[Severity.MEDIUM] == 0
        assert summary[Severity.LOW] == 0

    def test_graceful_error_handling_when_rule_raises(self) -> None:
        class FaultyRule(BaseRule):
            rule_id = "WARD-999"
            benchmark_ref = "TEST"
            title = "Faulty Test Rule"
            default_severity = Severity.HIGH
            description = "Fails intentionally"

            def evaluate(self, telemetry: ContainerTelemetry) -> list[Finding]:
                raise RuntimeError("Unexpected rule crash")

        engine = PolicyEngine(rules=[FaultyRule()])
        telemetry = create_telemetry_fixture()
        findings = engine.audit_container(telemetry)

        assert len(findings) == 1
        assert findings[0].rule_id == "WARD-999"
        assert "Rule evaluation error" in findings[0].title
        assert findings[0].severity == Severity.INFO
