"""Typed telemetry models for container runtime security inspection."""

from typing import Any
from pydantic import BaseModel, Field, computed_field


class ContainerIdentity(BaseModel):
    """Core identity attributes of an audited container."""

    id: str = Field(description="Full SHA256 hex container identifier")
    short_id: str = Field(description="Abbreviated 12-character container identifier")
    name: str = Field(description="Normalized container name without leading slash")
    image: str = Field(description="Image name and tag or digest used to spawn the container")
    status: str = Field(description="Container lifecycle status (running, paused, created, etc.)")
    created_at: str = Field(description="ISO 8601 creation timestamp")


class ExecutionSecurity(BaseModel):
    """Security attributes defining user privilege, rootfs state, and kernel mitigations."""

    user: str = Field(
        default="",
        description="Declared runtime user (empty string indicates image default root)",
    )
    privileged: bool = Field(
        default=False,
        description="True if container runs with --privileged flag (bypasses all isolation)",
    )
    read_only_rootfs: bool = Field(
        default=False,
        description="True if root filesystem is mounted read-only (--read-only)",
    )
    security_opt: list[str] = Field(
        default_factory=list,
        description="Raw security-opt flags passed to runtime (seccomp, apparmor, etc.)",
    )
    no_new_privileges: bool = Field(
        default=False,
        description="True if process cannot gain additional privileges via setuid/setgid",
    )
    apparmor_profile: str = Field(
        default="",
        description="Active AppArmor profile name or 'unconfined'",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_root(self) -> bool:
        """Determines if the container executes under root user (UID 0).

        In Docker, an empty user string, '0', 'root', or UID 0 in 'UID:GID'
        format executes as root inside the container namespace.
        """
        u = self.user.strip().lower()
        if not u or u == "0" or u == "root":
            return True
        if u.startswith("0:"):
            return True
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def seccomp_unconfined(self) -> bool:
        """True if the default seccomp filter has been explicitly disabled."""
        for opt in self.security_opt:
            normalized = opt.strip().lower()
            if "seccomp=unconfined" in normalized or "seccomp:unconfined" in normalized:
                return True
        return False


class LinuxCapabilities(BaseModel):
    """Linux kernel capabilities granted or removed from the container."""

    cap_add: list[str] = Field(
        default_factory=list,
        description="Capabilities explicitly added beyond default (--cap-add)",
    )
    cap_drop: list[str] = Field(
        default_factory=list,
        description="Capabilities explicitly dropped (--cap-drop)",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def drops_all(self) -> bool:
        """True if the container applies the recommended baseline --cap-drop=ALL."""
        return any(c.upper() == "ALL" for c in self.cap_drop)


class ResourceLimits(BaseModel):
    """Resource constraints enforced through Linux cgroups v1/v2."""

    memory_bytes: int = Field(
        default=0,
        description="Memory ceiling in bytes (0 indicates unlimited host memory allocation)",
    )
    nano_cpus: int = Field(
        default=0,
        description="CPU quota expressed in fractions of a CPU as 1e-9 (0 indicates unlimited)",
    )
    cpu_quota: int = Field(
        default=0,
        description="CFS CPU quota in microseconds per period (0 or -1 indicates unlimited)",
    )
    cpu_period: int = Field(
        default=0,
        description="CFS CPU period in microseconds",
    )
    pids_limit: int | None = Field(
        default=None,
        description="Maximum concurrent PIDs allowed in the cgroup (prevents fork bombs)",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_memory_limit(self) -> bool:
        """True if a valid memory constraint is active."""
        return self.memory_bytes > 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_cpu_limit(self) -> bool:
        """True if a CPU constraint (nano_cpus or cpu_quota) is active."""
        return self.nano_cpus > 0 or self.cpu_quota > 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def has_pids_limit(self) -> bool:
        """True if a PIDs constraint is enforced."""
        return self.pids_limit is not None and self.pids_limit > 0


class PortBinding(BaseModel):
    """Network port mapping exposed by the container."""

    container_port: str = Field(description="Container internal port and protocol (e.g. '80/tcp')")
    host_ip: str = Field(description="Host interface IP binding ('0.0.0.0', '127.0.0.1', '::')")
    host_port: str = Field(description="Port number exposed on the host interface")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_publicly_exposed(self) -> bool:
        """True if bound to all interfaces (0.0.0.0 or ::), exposing it externally."""
        ip = self.host_ip.strip()
        return ip in ("0.0.0.0", "::", "")


class NetworkExposition(BaseModel):
    """Networking stack configuration and port exposure details."""

    network_mode: str = Field(
        default="bridge",
        description="Docker network driver mode (bridge, host, none, container:id)",
    )
    port_bindings: list[PortBinding] = Field(
        default_factory=list,
        description="List of published host port mappings",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def shares_host_network(self) -> bool:
        """True if container bypasses network namespaces using --network=host."""
        return self.network_mode.strip().lower() == "host"


class MountInspection(BaseModel):
    """Mounted filesystem, volume, or bind mount within the container."""

    source: str = Field(description="Host filesystem path or named volume name")
    destination: str = Field(description="Mount point path inside container")
    mode: str = Field(default="rw", description="Access mode ('ro' for read-only, 'rw' for read-write)")
    mount_type: str = Field(default="bind", description="Type of mount: bind, volume, tmpfs")
    rw: bool = Field(default=True, description="True if filesystem is mounted read-write")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_docker_socket(self) -> bool:
        """True if mount exposes the host Docker daemon socket (/var/run/docker.sock)."""
        src = self.source.lower()
        dst = self.destination.lower()
        return "docker.sock" in src or "docker.sock" in dst

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_root_or_system_directory(self) -> bool:
        """True if mount gives read-write access to critical host operating system paths."""
        sensitive_prefixes = ("/etc", "/root", "/var/run", "/proc", "/sys", "/boot")
        src = self.source
        return src == "/" or any(src.startswith(prefix) for prefix in sensitive_prefixes)


class ContainerTelemetry(BaseModel):
    """Complete audited snapshot of a running container's configuration and security state."""

    identity: ContainerIdentity
    security: ExecutionSecurity
    capabilities: LinuxCapabilities
    resources: ResourceLimits
    network: NetworkExposition
    mounts: list[MountInspection] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
