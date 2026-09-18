"""Registry of all concrete DockerWard runtime security rules."""

from dockerward.rules.definitions.capabilities import CapabilitiesRule
from dockerward.rules.definitions.docker_socket import DockerSocketRule
from dockerward.rules.definitions.privileged_mode import PrivilegedModeRule
from dockerward.rules.definitions.resource_limits import ResourceLimitsRule
from dockerward.rules.definitions.root_user import RootUserRule
from dockerward.rules.definitions.seccomp import SeccompRule

ALL_RULES = [
    RootUserRule(),
    PrivilegedModeRule(),
    DockerSocketRule(),
    ResourceLimitsRule(),
    CapabilitiesRule(),
    SeccompRule(),
]

__all__ = [
    "ALL_RULES",
    "CapabilitiesRule",
    "DockerSocketRule",
    "PrivilegedModeRule",
    "ResourceLimitsRule",
    "RootUserRule",
    "SeccompRule",
]
