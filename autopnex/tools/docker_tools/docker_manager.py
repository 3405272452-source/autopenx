"""Docker container manager for Shannon tools integration.

Manages the lifecycle of a Docker container pre-loaded with 600+ Kali Linux
security tools (nmap, nuclei, hydra, sqlmap, gowitness, etc.).
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("autopnex.docker")


@dataclass
class DockerResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


class DockerManager:
    """Singleton Docker container manager."""

    _instance: Optional["DockerManager"] = None

    def __init__(self, image: str = "shannon-tools", container_name: str = "autopnex-shannon") -> None:
        self.image = image
        self.container_name = container_name
        self._client = None
        self._running = False

    @classmethod
    def get_instance(cls, image: str = "shannon-tools") -> "DockerManager":
        if cls._instance is None:
            cls._instance = cls(image=image)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    def _get_client(self):
        if self._client is None:
            try:
                import docker
                self._client = docker.from_env()
            except Exception as exc:
                raise RuntimeError(
                    f"Docker SDK not available: {exc}. "
                    "Install with: pip install docker"
                ) from exc
        return self._client

    def is_available(self) -> bool:
        """Check if Docker daemon is reachable."""
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception:
            return False

    def ensure_running(self) -> None:
        """Start the container if not already running."""
        if self._running:
            return

        client = self._get_client()

        # Check if container already exists
        try:
            container = client.containers.get(self.container_name)
            if container.status == "running":
                self._running = True
                return
            container.start()
            self._running = True
            return
        except Exception:
            pass

        # Create and start new container
        try:
            client.containers.run(
                self.image,
                name=self.container_name,
                detach=True,
                tty=True,
                stdin_open=True,
                # Mount current directory for file access
                volumes={},
                # Network host for direct target access
                network_mode="host",
                # Security: drop all capabilities
                cap_drop=["ALL"],
                # Remove on stop
                remove=False,
            )
            self._running = True
            log.info("Started Docker container: %s", self.container_name)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to start Docker container '{self.container_name}' "
                f"with image '{self.image}': {exc}\n"
                "Build the image first: docker build -t shannon-tools ."
            ) from exc

    def exec_command(self, command: str, timeout: int = 300000) -> DockerResult:
        """Execute a command inside the running container.

        Args:
            command: Shell command to execute.
            timeout: Timeout in milliseconds.

        Returns:
            DockerResult with exit_code, stdout, stderr, duration_ms.
        """
        self.ensure_running()
        client = self._get_client()
        container = client.containers.get(self.container_name)

        start = time.perf_counter()
        try:
            exit_code, output = container.exec_run(
                cmd=["sh", "-c", command],
                demux=True,
                stdout=True,
                stderr=True,
                timeout=timeout / 1000 if timeout else None,
            )
            stdout = (output[0] or b"").decode("utf-8", errors="replace")
            stderr = (output[1] or b"").decode("utf-8", errors="replace")
        except Exception as exc:
            return DockerResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=int((time.perf_counter() - start) * 1000),
            )

        return DockerResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=int((time.perf_counter() - start) * 1000),
        )

    def cleanup(self) -> None:
        """Stop and remove the container."""
        try:
            client = self._get_client()
            container = client.containers.get(self.container_name)
            container.stop(timeout=5)
            container.remove(force=True)
            log.info("Cleaned up Docker container: %s", self.container_name)
        except Exception:
            pass
        self._running = False

    # ---- Local execution helpers -----------------------------------------

    @staticmethod
    def find_binary(name: str) -> Optional[str]:
        """Return the full path of a local binary, or None."""
        return shutil.which(name)

    @staticmethod
    def exec_local(command: str, timeout: int = 300000) -> "DockerResult":
        """Execute a command on the local machine via subprocess.

        Args:
            command: Shell command to execute.
            timeout: Timeout in milliseconds.

        Returns:
            DockerResult with exit_code, stdout, stderr, duration_ms.
        """
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout / 1000 if timeout else None,
            )
            return DockerResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
        except subprocess.TimeoutExpired:
            return DockerResult(
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}ms",
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
        except Exception as exc:
            return DockerResult(
                exit_code=-1,
                stdout="",
                stderr=str(exc),
                duration_ms=int((time.perf_counter() - start) * 1000),
            )
