"""Native worker integration boundary.

The worker protocol is length-prefixed JSON control messages in v1. Flow batches
are carried as compact records under ``flows`` and are immediately converted to
Python feature dictionaries for the existing detector contract. The client never
loads an unbounded worker response into memory.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterator

MAX_MESSAGE = 64 * 1024 * 1024
HEADER = struct.Struct("<I")


class WorkerUnavailable(RuntimeError):
    pass


def _worker_path() -> str | None:
    configured = os.environ.get("QDS_VULKAN_WORKER")
    if configured and Path(configured).exists():
        return configured
    candidate = Path(__file__).resolve().parents[2] / "native_worker" / "build" / "Release" / "qds_vulkan_worker.exe"
    return str(candidate) if candidate.exists() else None


class VulkanWorkerClient:
    def __init__(self, executable: str | None = None, batch_size: int = 4096):
        self.executable = executable or _worker_path()
        self.batch_size = batch_size

    def capabilities(self) -> dict[str, Any]:
        if not self.executable:
            return {"available": False, "backend": "cpu", "reason": "worker_not_installed"}
        try:
            result = subprocess.run([self.executable, "--capabilities"], capture_output=True, text=True, timeout=5)
            payload = json.loads(result.stdout) if result.stdout.strip() else {}
            return {"available": result.returncode == 0 and payload.get("backend") == "vulkan", **payload}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            return {"available": False, "backend": "cpu", "reason": str(exc)}

    def process_pcap(self, path: str) -> Iterator[list[dict[str, Any]]]:
        caps = self.capabilities()
        if not caps.get("available") or not caps.get("process_pcap"):
            raise WorkerUnavailable(caps.get("reason", "worker does not support process_pcap"))
        process = subprocess.Popen(
            [self.executable, "--process-pcap", path, "--batch-size", str(self.batch_size)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None
        try:
            while True:
                header = process.stdout.read(HEADER.size)
                if not header:
                    break
                if len(header) != HEADER.size:
                    raise WorkerUnavailable("truncated worker response header")
                size = HEADER.unpack(header)[0]
                if size > MAX_MESSAGE:
                    raise WorkerUnavailable("worker response exceeds 64 MiB")
                body = process.stdout.read(size)
                if len(body) != size:
                    raise WorkerUnavailable("truncated worker response body")
                payload = json.loads(body)
                if payload.get("status") == "ERROR":
                    raise WorkerUnavailable(payload.get("error", "native worker failed"))
                yield payload.get("flows", [])
            if process.wait(timeout=5) != 0:
                error = process.stderr.read().decode(errors="replace") if process.stderr else ""
                raise WorkerUnavailable(error or "native worker failed")
        finally:
            if process.poll() is None:
                process.kill()
