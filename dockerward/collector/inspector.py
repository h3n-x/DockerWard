"""Extracts and parses low-level container configuration into structured telemetry models."""

from typing import Any
import docker
from docker.models.containers import Container

from dockerward.collector.client import DockerClientManager
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


class ContainerInspector:
    """Orchestrates runtime inspection across Docker daemon containers."""

    def __init__(self, client_manager: DockerClientManager | None = None) -> None:
        """Initialize inspector with a client manager.

        Args:
            client_manager: Optional instance of DockerClientManager.
                            If omitted, initializes a default manager.
        """
        self.client_manager = client_manager or DockerClientManager()

    def inspect_all(self, only_running: bool = True) -> list[ContainerTelemetry]:
        """Inspect all available containers on the host.

        Args:
            only_running: If True, audits only containers with 'running' status.
                          If False, inspects all containers regardless of state.

        Returns:
            list[ContainerTelemetry]: List of parsed container telemetry models.
        """
        client = self.client_manager.get_client()
        containers = client.containers.list(all=not only_running)
        return [self.parse_container(c) for c in containers]

    def inspect_by_id_or_name(self, target: str) -> ContainerTelemetry:
        """Inspect a single specific container by name, full ID, or prefix.

        Args:
            target: Container identifier or name.

        Returns:
            ContainerTelemetry: Audited telemetry snapshot.
        """
        client = self.client_manager.get_client()
        container = client.containers.get(target)
        return self.parse_container(container)

    def parse_container(self, container: Container) -> ContainerTelemetry:
        """Transform raw Docker SDK container inspection attributes into typed telemetry.

        Args:
            container: Raw Docker container object.

        Returns:
            ContainerTelemetry: Strongly-typed security telemetry model.
        """
        # Ensure fresh in-memory attributes are loaded
        container.reload()
        raw = container.attrs

        config = raw.get("Config") or {}
        host_config = raw.get("HostConfig") or {}
        state = raw.get("State") or {}
        network_settings = raw.get("NetworkSettings") or {}

        # 1. Identity
        full_id = raw.get("Id", container.id or "")
        short_id = full_id[:12] if len(full_id) >= 12 else full_id
        raw_name = raw.get("Name", container.name or "")
        normalized_name = raw_name.lstrip("/")
        image_name = config.get("Image", "")

        identity = ContainerIdentity(
            id=full_id,
            short_id=short_id,
            name=normalized_name,
            image=image_name,
            status=state.get("Status", "unknown"),
            created_at=raw.get("Created", ""),
        )

        # 2. Execution & Kernel Security
        security_opts = host_config.get("SecurityOpt") or []
        user_str = config.get("User") or ""
        apparmor_profile = raw.get("AppArmorProfile") or ""

        security = ExecutionSecurity(
            user=user_str,
            privileged=bool(host_config.get("Privileged", False)),
            read_only_rootfs=bool(host_config.get("ReadonlyRootfs", False)),
            security_opt=[str(opt) for opt in security_opts],
            no_new_privileges=bool(host_config.get("NoNewPrivileges", False)),
            apparmor_profile=apparmor_profile,
        )

        # 3. Linux Capabilities
        cap_add = [str(c) for c in (host_config.get("CapAdd") or [])]
        cap_drop = [str(c) for c in (host_config.get("CapDrop") or [])]
        capabilities = LinuxCapabilities(cap_add=cap_add, cap_drop=cap_drop)

        # 4. Resource Constraints (cgroups)
        memory_bytes = int(host_config.get("Memory") or 0)
        nano_cpus = int(host_config.get("NanoCpus") or host_config.get("NanoCPUs") or 0)
        cpu_quota = int(host_config.get("CpuQuota") or 0)
        cpu_period = int(host_config.get("CpuPeriod") or 0)
        pids_limit_raw = host_config.get("PidsLimit")
        pids_limit = int(pids_limit_raw) if pids_limit_raw not in (None, 0) else None

        resources = ResourceLimits(
            memory_bytes=memory_bytes,
            nano_cpus=nano_cpus,
            cpu_quota=cpu_quota,
            cpu_period=cpu_period,
            pids_limit=pids_limit,
        )

        # 5. Network Stack & Exposed Ports
        network_mode = str(host_config.get("NetworkMode") or "bridge")
        port_bindings: list[PortBinding] = []
        raw_ports = network_settings.get("Ports") or {}

        for container_port, bindings in raw_ports.items():
            if not bindings:
                continue
            for b in bindings:
                host_ip = b.get("HostIp", "0.0.0.0")
                host_port = b.get("HostPort", "")
                port_bindings.append(
                    PortBinding(
                        container_port=str(container_port),
                        host_ip=str(host_ip),
                        host_port=str(host_port),
                    )
                )

        network = NetworkExposition(
            network_mode=network_mode,
            port_bindings=port_bindings,
        )

        # 6. Filesystem Mounts & Binds
        mounts: list[MountInspection] = []
        raw_mounts = raw.get("Mounts") or []

        for m in raw_mounts:
            source = str(m.get("Source", ""))
            destination = str(m.get("Destination", ""))
            mode = str(m.get("Mode", "rw"))
            rw = bool(m.get("RW", True))
            m_type = str(m.get("Type", "bind"))

            mounts.append(
                MountInspection(
                    source=source,
                    destination=destination,
                    mode=mode,
                    mount_type=m_type,
                    rw=rw,
                )
            )

        # Fallback check: parse legacy HostConfig.Binds if Mounts is empty
        if not mounts and host_config.get("Binds"):
            for bind in host_config.get("Binds") or []:
                parts = str(bind).split(":")
                if len(parts) >= 2:
                    src = parts[0]
                    dst = parts[1]
                    m_mode = parts[2] if len(parts) >= 3 else "rw"
                    mounts.append(
                        MountInspection(
                            source=src,
                            destination=dst,
                            mode=m_mode,
                            mount_type="bind",
                            rw="rw" in m_mode or m_mode == "",
                        )
                    )

        # 7. Metadata Labels
        raw_labels = config.get("Labels") or {}
        labels = {str(k): str(v) for k, v in raw_labels.items()}

        return ContainerTelemetry(
            identity=identity,
            security=security,
            capabilities=capabilities,
            resources=resources,
            network=network,
            mounts=mounts,
            labels=labels,
        )
