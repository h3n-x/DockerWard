"""Collector module for DockerWard: telemetry extraction from Docker daemon."""

from dockerward.collector.client import DockerClientManager
from dockerward.collector.inspector import ContainerInspector
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

__all__ = [
    "ContainerIdentity",
    "ContainerInspector",
    "ContainerTelemetry",
    "DockerClientManager",
    "ExecutionSecurity",
    "LinuxCapabilities",
    "MountInspection",
    "NetworkExposition",
    "PortBinding",
    "ResourceLimits",
]
