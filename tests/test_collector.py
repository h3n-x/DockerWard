"""Unit tests for telemetry models and container inspection parsing."""

from unittest.mock import MagicMock
import pytest

from dockerward.collector.inspector import ContainerInspector
from dockerward.collector.models import (
    ContainerIdentity,
    ExecutionSecurity,
    LinuxCapabilities,
    MountInspection,
    NetworkExposition,
    PortBinding,
    ResourceLimits,
)


class TestExecutionSecurity:
    """Test computed properties on security context."""

    @pytest.mark.parametrize(
        ("user", "expected_root"),
        [
            ("", True),
            ("root", True),
            ("0", True),
            ("0:0", True),
            ("ROOT", True),
            ("1000", False),
            ("1000:1000", False),
            ("nobody", False),
            ("appuser", False),
        ],
    )
    def test_is_root_detection(self, user: str, expected_root: bool) -> None:
        sec = ExecutionSecurity(user=user)
        assert sec.is_root is expected_root

    @pytest.mark.parametrize(
        ("security_opt", "expected_unconfined"),
        [
            ([], False),
            (["apparmor=docker-default"], False),
            (["seccomp=unconfined"], True),
            (["seccomp:unconfined"], True),
            (["SECCOMP=UNCONFINED"], True),
        ],
    )
    def test_seccomp_unconfined(self, security_opt: list[str], expected_unconfined: bool) -> None:
        sec = ExecutionSecurity(security_opt=security_opt)
        assert sec.seccomp_unconfined is expected_unconfined


class TestLinuxCapabilities:
    """Test capability drop evaluation."""

    def test_drops_all(self) -> None:
        caps_safe = LinuxCapabilities(cap_drop=["ALL"])
        assert caps_safe.drops_all is True

        caps_case = LinuxCapabilities(cap_drop=["all"])
        assert caps_case.drops_all is True

        caps_partial = LinuxCapabilities(cap_drop=["NET_RAW", "SYS_CHROOT"])
        assert caps_partial.drops_all is False


class TestResourceLimits:
    """Test cgroups resource constraint detection."""

    def test_resource_limits_flags(self) -> None:
        unbounded = ResourceLimits(memory_bytes=0, nano_cpus=0, pids_limit=None)
        assert unbounded.has_memory_limit is False
        assert unbounded.has_cpu_limit is False
        assert unbounded.has_pids_limit is False

        bounded = ResourceLimits(
            memory_bytes=134217728,  # 128 MB
            nano_cpus=500000000,    # 0.5 CPU
            pids_limit=50,
        )
        assert bounded.has_memory_limit is True
        assert bounded.has_cpu_limit is True
        assert bounded.has_pids_limit is True


class TestMountInspection:
    """Test filesystem mount security properties."""

    def test_docker_socket_detection(self) -> None:
        sock_mount = MountInspection(
            source="/var/run/docker.sock",
            destination="/var/run/docker.sock",
            mode="rw",
        )
        assert sock_mount.is_docker_socket is True
        assert sock_mount.is_root_or_system_directory is True

        normal_mount = MountInspection(
            source="/data/app",
            destination="/app/data",
            mode="ro",
        )
        assert normal_mount.is_docker_socket is False
        assert normal_mount.is_root_or_system_directory is False


class TestContainerInspectorParsing:
    """Test parsing raw Docker engine attributes into typed ContainerTelemetry."""

    def test_parse_mock_container(self) -> None:
        mock_container = MagicMock()
        mock_container.id = "abcdef1234567890abcdef1234567890"
        mock_container.name = "/vulnerable-prod-db"
        mock_container.attrs = {
            "Id": "abcdef1234567890abcdef1234567890",
            "Name": "/vulnerable-prod-db",
            "Created": "2026-09-17T12:00:00Z",
            "State": {"Status": "running"},
            "Config": {
                "Image": "postgres:16-alpine",
                "User": "0:0",
                "Labels": {"env": "prod"},
            },
            "HostConfig": {
                "Privileged": True,
                "ReadonlyRootfs": False,
                "SecurityOpt": ["seccomp:unconfined"],
                "CapAdd": ["SYS_ADMIN"],
                "CapDrop": [],
                "Memory": 0,
                "NanoCPUs": 0,
                "PidsLimit": None,
                "NetworkMode": "host",
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock:rw"],
            },
            "NetworkSettings": {"Ports": {}},
            "Mounts": [
                {
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                    "Mode": "rw",
                    "RW": True,
                    "Type": "bind",
                }
            ],
        }

        inspector = ContainerInspector(client_manager=MagicMock())
        telemetry = inspector.parse_container(mock_container)

        assert telemetry.identity.short_id == "abcdef123456"
        assert telemetry.identity.name == "vulnerable-prod-db"
        assert telemetry.identity.image == "postgres:16-alpine"
        assert telemetry.security.is_root is True
        assert telemetry.security.privileged is True
        assert telemetry.security.seccomp_unconfined is True
        assert telemetry.capabilities.cap_add == ["SYS_ADMIN"]
        assert telemetry.resources.has_memory_limit is False
        assert telemetry.network.shares_host_network is True
        assert len(telemetry.mounts) == 1
        assert telemetry.mounts[0].is_docker_socket is True
