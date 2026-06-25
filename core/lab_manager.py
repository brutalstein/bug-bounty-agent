from __future__ import annotations

from dataclasses import dataclass, asdict
import subprocess
import time

from core.http_client import SafeHttpClient
from core.scope import ScopeManager


@dataclass
class LabStatus:
    profile_name: str
    container_name: str
    docker_image: str
    published_port: int
    container_port: int
    docker_available: bool
    container_present: bool
    container_running: bool
    docker_status_text: str
    reachable_over_http: bool
    http_status_code: int | None
    error: str | None

    def to_dict(self) -> dict:
        return asdict(self)


class LabManager:
    def __init__(self, scope: ScopeManager):
        self.scope = scope
        self.client = SafeHttpClient(timeout_seconds=5)

        if not self.scope.config.lab:
            raise ValueError("Selected profile does not define a lab configuration.")

        self.lab = self.scope.config.lab

    def status(self) -> LabStatus:
        docker_available = True
        container_present = False
        container_running = False
        docker_status_text = ""
        error = None

        command = [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"name={self.lab.container_name}",
            "--format",
            "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}",
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:
            docker_available = False
            error = str(exc)
            process = None

        if process is not None and process.returncode == 0:
            output = (process.stdout or "").strip()
            if output:
                container_present = True
                docker_status_text = output
                container_running = "Up " in output or " Up " in output or output.endswith("|")
                if "Exited" in output or "Created" in output:
                    container_running = False
            else:
                docker_status_text = "container_not_found"
        elif process is not None:
            docker_available = False
            error = (process.stderr or process.stdout).strip() or f"docker return code {process.returncode}"

        target_url = self.scope.config.base_url
        response = self.client.get(target_url)
        reachable_over_http = response.status_code is not None

        return LabStatus(
            profile_name=self.scope.config.profile_name,
            container_name=self.lab.container_name,
            docker_image=self.lab.docker_image,
            published_port=self.lab.published_port,
            container_port=self.lab.container_port,
            docker_available=docker_available,
            container_present=container_present,
            container_running=container_running,
            docker_status_text=docker_status_text,
            reachable_over_http=reachable_over_http,
            http_status_code=response.status_code,
            error=error or response.error,
        )

    def up(self) -> tuple[bool, str]:
        existing = self.status()
        if existing.container_running:
            readiness = self._wait_for_http_ready()
            if readiness:
                return True, f"Lab is already running on port {existing.published_port}."
            return False, "Lab container is running but HTTP health did not become ready in time."

        command = [
            "docker",
            "run",
            "--rm",
            "-d",
            "-p",
            f"{self.lab.published_port}:{self.lab.container_port}",
            "--name",
            self.lab.container_name,
            self.lab.docker_image,
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if process.returncode != 0:
            return False, (process.stderr or process.stdout).strip() or "docker run failed"

        readiness = self._wait_for_http_ready()
        if not readiness:
            return False, "Lab container started, but HTTP health did not become ready in time."

        return True, (process.stdout or "").strip() or "lab_started"

    def down(self) -> tuple[bool, str]:
        command = ["docker", "rm", "-f", self.lab.container_name]
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        if process.returncode != 0:
            output = (process.stderr or process.stdout).strip()
            if "No such container" in output:
                return True, "lab_container_not_present"
            return False, output or "docker rm failed"

        return True, (process.stdout or "").strip() or "lab_stopped"

    def _wait_for_http_ready(self, timeout_seconds: int = 30) -> bool:
        deadline = time.time() + timeout_seconds

        while time.time() < deadline:
            response = self.client.get(self.scope.config.base_url)
            if response.status_code is not None:
                return True
            time.sleep(1)

        return False
