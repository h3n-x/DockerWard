"""Unit tests for DockerWard command line interface."""

from unittest.mock import MagicMock, patch
import pytest

from dockerward.cli import cmd_audit, cmd_inspect, cmd_ping, format_bytes, main
from dockerward.collector.client import DockerConnectionError
from dockerward.collector.models import (
    ContainerIdentity,
    ContainerTelemetry,
    ExecutionSecurity,
    LinuxCapabilities,
    MountInspection,
    NetworkExposition,
    PortBinding,
    ResourceLimits,
)
from dockerward.rules.engine import PolicyEngine
from dockerward.rules.models import Finding, Severity


def create_sample_telemetry(name: str = "victim-box", is_root: bool = True) -> ContainerTelemetry:
    """Produce a sample telemetry snapshot for CLI testing."""
    return ContainerTelemetry(
        identity=ContainerIdentity(
            id="1234567890abcdef" * 4,
            short_id="1234567890ab",
            name=name,
            image="test:latest",
            status="running",
            created_at="2026-09-17T00:00:00Z",
        ),
        security=ExecutionSecurity(
            user="root" if is_root else "1000:1000",
            privileged=is_root,
            read_only_rootfs=not is_root,
            security_opt=["seccomp:unconfined"] if is_root else [],
            no_new_privileges=not is_root,
        ),
        capabilities=LinuxCapabilities(
            cap_add=["SYS_ADMIN"] if is_root else [],
            cap_drop=[] if is_root else ["ALL"],
        ),
        resources=ResourceLimits(
            memory_bytes=0 if is_root else 268435456,
            nano_cpus=0 if is_root else 1000000000,
            pids_limit=None if is_root else 50,
        ),
        network=NetworkExposition(
            network_mode="host" if is_root else "bridge",
            port_bindings=[
                PortBinding(container_port="80/tcp", host_ip="0.0.0.0", host_port="8080")
            ] if is_root else [],
        ),
        mounts=[
            MountInspection(
                source="/var/run/docker.sock",
                destination="/var/run/docker.sock",
                mode="rw",
                rw=True,
            )
        ] if is_root else [],
        labels={},
    )


def test_format_bytes() -> None:
    assert "Unlimited" in format_bytes(0)
    assert "Unlimited" in format_bytes(-1)
    assert "512.0 MB" in format_bytes(536870912)
    assert "1.0 GB" in format_bytes(1073741824)


def test_cmd_ping_success() -> None:
    mgr = MagicMock()
    assert cmd_ping(mgr) == 0


def test_cmd_ping_failure() -> None:
    mgr = MagicMock()
    mgr.get_client.side_effect = DockerConnectionError("Socket missing", hint="Check dockerd")
    assert cmd_ping(mgr) == 1


def test_cmd_inspect_empty() -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = []
    assert cmd_inspect(inspector, target=None, as_json=False) == 0


def test_cmd_inspect_with_target_table() -> None:
    inspector = MagicMock()
    inspector.inspect_by_id_or_name.return_value = create_sample_telemetry()
    assert cmd_inspect(inspector, target="my-box", as_json=False) == 0


def test_cmd_inspect_as_json() -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = [create_sample_telemetry()]
    assert cmd_inspect(inspector, target=None, as_json=True) == 0


def test_cmd_inspect_exception() -> None:
    inspector = MagicMock()
    inspector.inspect_all.side_effect = RuntimeError("Inspect boom")
    assert cmd_inspect(inspector, target=None, as_json=False) == 1


def test_cmd_audit_empty(tmp_path: Any) -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = []
    engine = PolicyEngine()
    # table format
    assert cmd_audit(inspector, engine, target=None, format_type="table") == 0
    # sarif format with file output
    sarif_file = tmp_path / "empty.sarif"
    assert cmd_audit(inspector, engine, target=None, format_type="sarif", output_file=str(sarif_file)) == 0
    assert sarif_file.exists()
    # json format with file output
    json_file = tmp_path / "empty.json"
    assert cmd_audit(inspector, engine, target=None, format_type="json", output_file=str(json_file)) == 0
    assert json_file.exists()


def test_cmd_audit_hardened_container() -> None:
    inspector = MagicMock()
    inspector.inspect_by_id_or_name.return_value = create_sample_telemetry(name="safe-box", is_root=False)
    engine = PolicyEngine()
    assert cmd_audit(inspector, engine, target="safe-box", format_type="table") == 0


def test_cmd_audit_vulnerable_container_table() -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = [create_sample_telemetry(name="vuln-box", is_root=True)]
    engine = PolicyEngine()
    assert cmd_audit(inspector, engine, target=None, format_type="table") == 0


def test_cmd_audit_with_json_output(tmp_path: Any) -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = [create_sample_telemetry(name="vuln-box", is_root=True)]
    engine = PolicyEngine()
    json_out = tmp_path / "test.json"
    assert cmd_audit(
        inspector, engine, target=None, format_type="json", output_file=str(json_out), min_severity_str="HIGH"
    ) == 0
    assert json_out.exists()


def test_cmd_audit_with_sarif_output(tmp_path: Any) -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = [create_sample_telemetry(name="vuln-box", is_root=True)]
    engine = PolicyEngine()
    sarif_out = tmp_path / "test.sarif"
    assert cmd_audit(
        inspector, engine, target=None, format_type="sarif", output_file=str(sarif_out)
    ) == 0
    assert sarif_out.exists()


def test_cmd_audit_fail_on_threshold() -> None:
    inspector = MagicMock()
    inspector.inspect_all.return_value = [create_sample_telemetry(name="vuln-box", is_root=True)]
    engine = PolicyEngine()
    # Fails because vulnerable container has CRITICAL findings
    ret = cmd_audit(inspector, engine, target=None, format_type="table", fail_on_str="CRITICAL")
    assert ret == 1

    # Returns 0 if fail_on is higher than any findings (or when no findings meet threshold)
    clean_inspector = MagicMock()
    clean_inspector.inspect_all.return_value = [create_sample_telemetry(name="safe-box", is_root=False)]
    clean_ret = cmd_audit(clean_inspector, engine, target=None, format_type="table", fail_on_str="CRITICAL")
    assert clean_ret == 0


def test_cmd_audit_exception() -> None:
    inspector = MagicMock()
    inspector.inspect_all.side_effect = RuntimeError("Docker API timeout")
    engine = PolicyEngine()
    assert cmd_audit(inspector, engine, target=None, format_type="table") == 1


def test_main_cli_router(monkeypatch: pytest.MonkeyPatch) -> None:
    with patch("dockerward.cli.cmd_ping", return_value=0) as mock_ping:
        monkeypatch.setattr("sys.argv", ["dockerward", "ping"])
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        mock_ping.assert_called_once()
