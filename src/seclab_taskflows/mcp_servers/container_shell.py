# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import atexit
import hashlib
import json
import logging
import os
import subprocess
import uuid
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("container_shell.log"),
    filemode="a",
)

mcp = FastMCP("ContainerShell")

_container_name: str | None = None

CONTAINER_IMAGE = os.environ.get("CONTAINER_IMAGE", "")
CONTAINER_WORKSPACE = os.environ.get("CONTAINER_WORKSPACE", "")
CONTAINER_TIMEOUT = int(os.environ.get("CONTAINER_TIMEOUT", "30"))
CONTAINER_PERSIST = os.environ.get("CONTAINER_PERSIST", "").lower() in ("1", "true", "yes")
CONTAINER_PERSIST_KEY = os.environ.get("CONTAINER_PERSIST_KEY", "")

_DEFAULT_WORKDIR = "/workspace"
_DOCKER_TIMEOUT = 30


def _persistent_name() -> str:
    """Derive a deterministic container name from the image for reuse across tasks.

    Incorporates a hash of the full image reference (and optional
    CONTAINER_PERSIST_KEY) to avoid collisions between long image names that
    share a common prefix, or between independent runs of the same image.
    """
    key_material = CONTAINER_IMAGE
    if CONTAINER_PERSIST_KEY:
        key_material += f":{CONTAINER_PERSIST_KEY}"
    digest = hashlib.sha256(key_material.encode()).hexdigest()[:12]
    return f"seclab-persist-{digest}"


def _is_running(name: str) -> bool:
    """Check if a container with the given name is already running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "json", name],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return bool(data and data[0].get("State", {}).get("Running"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError):
        return False


def _remove_container(name: str) -> None:
    """Remove a stopped container by name. Logs failures for diagnostics.

    Uses ``docker rm`` (without -f) so that running containers are NOT
    killed — only genuinely stopped leftovers are cleaned up.
    """
    try:
        result = subprocess.run(
            ["docker", "rm", name],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            logging.debug(
                "docker rm skipped for %s: %s", name, result.stderr.strip()
            )
    except subprocess.TimeoutExpired:
        logging.exception("docker rm timed out for %s after %ds", name, _DOCKER_TIMEOUT)


def _start_container() -> str:
    """Start the Docker container and return its name."""
    if not CONTAINER_IMAGE:
        msg = "CONTAINER_IMAGE is not set — cannot start container"
        raise RuntimeError(msg)
    if CONTAINER_WORKSPACE and ":" in CONTAINER_WORKSPACE:
        msg = f"CONTAINER_WORKSPACE must not contain a colon: {CONTAINER_WORKSPACE!r}"
        raise RuntimeError(msg)

    if CONTAINER_PERSIST:
        name = _persistent_name()
        if _is_running(name):
            logging.debug(f"Reusing persistent container: {name}")
            return name
        # Remove stopped leftover with the same name
        _remove_container(name)
    else:
        name = f"seclab-shell-{uuid.uuid4().hex[:8]}"

    cmd = ["docker", "run", "-d", "--name", name]
    if not CONTAINER_PERSIST:
        cmd.append("--rm")
    if CONTAINER_WORKSPACE:
        cmd += ["-v", f"{CONTAINER_WORKSPACE}:/workspace"]
    cmd += [CONTAINER_IMAGE, "tail", "-f", "/dev/null"]
    logging.debug(f"Starting container: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=_DOCKER_TIMEOUT)
    if result.returncode != 0:
        msg = f"docker run failed: {result.stderr.strip()}"
        raise RuntimeError(msg)
    logging.debug(f"Container started: {name} (persist={CONTAINER_PERSIST})")
    return name


def _stop_container() -> None:
    """Stop the running container (skipped for persistent containers)."""
    global _container_name
    if _container_name is None:
        return
    if CONTAINER_PERSIST:
        logging.debug(f"Leaving persistent container running: {_container_name}")
        _container_name = None
        return
    logging.debug(f"Stopping container: {_container_name}")
    result = subprocess.run(
        ["docker", "stop", "--time", "5", _container_name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logging.warning(
            "docker stop failed for container %s: %s",
            _container_name,
            result.stderr.strip(),
        )
    _container_name = None


atexit.register(_stop_container)


@mcp.tool()
def shell_exec(
    command: Annotated[str, Field(description="Shell command to execute inside the container")],
    timeout: Annotated[int, Field(description="Timeout in seconds")] = CONTAINER_TIMEOUT,
    workdir: Annotated[str, Field(description="Working directory inside the container")] = _DEFAULT_WORKDIR,
) -> str:
    """Execute a shell command inside the managed Docker container."""
    global _container_name
    if _container_name is None:
        try:
            _container_name = _start_container()
        except RuntimeError as e:
            return f"Failed to start container: {e}"

    cmd = ["docker", "exec", "-w", workdir, _container_name, "bash", "-c", command]
    logging.debug(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"[exit code: timeout after {timeout}s]"

    output = result.stdout
    if result.stderr:
        output += result.stderr
    output += f"[exit code: {result.returncode}]"
    return output


if __name__ == "__main__":
    mcp.run(show_banner=False)
