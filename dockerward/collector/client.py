"""Docker daemon client connection management and diagnostics."""

import os
from typing import Any
import docker
from docker.errors import DockerException


class DockerConnectionError(Exception):
    """Raised when communication with the local or remote Docker daemon fails."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


class DockerClientManager:
    """Manages connectivity, health checks, and lifecycle of Docker SDK clients."""

    def __init__(self, base_url: str | None = None) -> None:
        """Initialize client manager.

        Args:
            base_url: Optional Docker socket or TCP URI (e.g. 'unix:///var/run/docker.sock').
                      If omitted, automatically reads standard environment variables (DOCKER_HOST).
        """
        self.base_url = base_url or os.environ.get("DOCKER_HOST")
        self._client: docker.DockerClient | None = None

    def get_client(self) -> docker.DockerClient:
        """Retrieve or initialize an active Docker client instance.

        Returns:
            docker.DockerClient: Authenticated and pinged client instance.

        Raises:
            DockerConnectionError: If daemon is inactive, socket is missing, or permission denied.
        """
        if self._client is not None:
            return self._client

        try:
            if self.base_url:
                client = docker.DockerClient(base_url=self.base_url)
            else:
                client = docker.from_env()

            # Verify connection health by issuing an explicit ping
            client.ping()
            self._client = client
            return self._client

        except DockerException as err:
            err_msg = str(err)
            hint = "Verify that the Docker service is running via 'systemctl status docker'."

            if "Permission denied" in err_msg or "permission denied" in err_msg.lower():
                hint = (
                    "User lacks permission to access '/var/run/docker.sock'. "
                    "Ensure your user belongs to the 'docker' group: "
                    "'sudo usermod -aG docker $USER' (then log out and back in)."
                )
            elif "FileNotFoundError" in err_msg or "No such file or directory" in err_msg:
                hint = (
                    "Docker socket '/var/run/docker.sock' does not exist. "
                    "Confirm the Docker engine is installed and active."
                )

            raise DockerConnectionError(
                f"Failed to connect to Docker daemon: {err_msg}",
                hint=hint,
            ) from err

    def ping(self) -> bool:
        """Quick check to confirm daemon responsiveness.

        Returns:
            bool: True if daemon responds, False otherwise.
        """
        try:
            client = self.get_client()
            return bool(client.ping())
        except DockerConnectionError:
            return False

    def close(self) -> None:
        """Close connection and release underlying HTTP connection pools."""
        if self._client is not None:
            self._client.close()
            self._client = None
