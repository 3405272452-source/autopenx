"""Docker-based vulnerable target management for benchmark testing."""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

log = logging.getLogger("autopnex.benchmark.targets")

CONTAINER_PREFIX = "autopnex-bench-"


@dataclass
class VulnerableTarget:
    name: str
    image: str
    port_mapping: str  # "host:container"
    url: str
    ready_path: str
    env_vars: Dict[str, str] = field(default_factory=dict)

    @property
    def host_port(self) -> int:
        return int(self.port_mapping.split(":")[0])

    @property
    def container_port(self) -> int:
        return int(self.port_mapping.split(":")[1])

    @property
    def container_name(self) -> str:
        return f"{CONTAINER_PREFIX}{self.name}"

    @property
    def ready_url(self) -> str:
        return f"{self.url}{self.ready_path}"


TARGETS: Dict[str, VulnerableTarget] = {
    "dvwa": VulnerableTarget(
        name="dvwa",
        image="vulnerables/web-dvwa",
        port_mapping="4280:80",
        url="http://localhost:4280",
        ready_path="/login.php",
    ),
    "juice-shop": VulnerableTarget(
        name="juice-shop",
        image="bkimminich/juice-shop",
        port_mapping="4300:3000",
        url="http://localhost:4300",
        ready_path="/",
    ),
    "webgoat": VulnerableTarget(
        name="webgoat",
        image="webgoat/webgoat",
        port_mapping="4380:8080",
        url="http://localhost:4380/WebGoat",
        ready_path="/WebGoat/login",
        env_vars={"WEBGOAT_PORT": "8080"},
    ),
}


def docker_available() -> bool:
    """Return True if Docker CLI is accessible and the daemon is running."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


class TargetManager:
    """Lifecycle manager for Docker-based vulnerable targets."""

    def __init__(self) -> None:
        self._running: Dict[str, VulnerableTarget] = {}

    def start(self, target_name: str, *, pull: bool = False) -> VulnerableTarget:
        """Start a target container. Returns the VulnerableTarget descriptor."""
        if target_name not in TARGETS:
            raise ValueError(f"Unknown target: {target_name!r}. Choose from {list(TARGETS)}")

        target = TARGETS[target_name]

        self._stop_container(target.container_name)

        if pull:
            log.info("Pulling image %s ...", target.image)
            subprocess.run(["docker", "pull", target.image], check=True, timeout=300)

        env_args: List[str] = []
        for key, value in target.env_vars.items():
            env_args.extend(["-e", f"{key}={value}"])

        cmd = [
            "docker", "run", "-d",
            "--name", target.container_name,
            "-p", target.port_mapping,
            *env_args,
            target.image,
        ]
        log.info("Starting %s: %s", target.name, " ".join(cmd))
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
        self._running[target_name] = target
        return target

    def stop(self, target_name: str) -> None:
        """Stop and remove a specific target container."""
        target = TARGETS.get(target_name)
        if target is None:
            return
        self._stop_container(target.container_name)
        self._running.pop(target_name, None)

    def stop_all(self) -> None:
        """Stop all running benchmark containers."""
        for name in list(self._running):
            self.stop(name)

    def is_ready(self, target: VulnerableTarget, timeout: int = 60) -> bool:
        """Poll the target's ready endpoint until it responds or timeout."""
        deadline = time.monotonic() + timeout
        interval = 2.0
        while time.monotonic() < deadline:
            try:
                resp = urlopen(target.ready_url, timeout=5)  # noqa: S310
                if 200 <= resp.status < 500:
                    log.info("Target %s is ready at %s", target.name, target.ready_url)
                    return True
            except (URLError, OSError, ConnectionError):
                pass
            time.sleep(interval)
            interval = min(interval * 1.2, 5.0)
        log.warning("Target %s did not become ready within %ds", target.name, timeout)
        return False

    def start_and_wait(
        self,
        target_name: str,
        *,
        pull: bool = False,
        timeout: int = 90,
    ) -> VulnerableTarget:
        """Start a target and block until it's healthy."""
        target = self.start(target_name, pull=pull)
        if not self.is_ready(target, timeout=timeout):
            self.stop(target_name)
            raise RuntimeError(
                f"Target {target_name!r} failed to become ready within {timeout}s"
            )
        return target

    @staticmethod
    def _stop_container(container_name: str) -> None:
        """Stop and remove a container by name, ignoring errors."""
        for action in ("stop", "rm"):
            try:
                subprocess.run(
                    ["docker", action, container_name],
                    capture_output=True,
                    timeout=30,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
