"""Optional native Vulkan worker discovery with safe CPU fallback."""
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class WorkerStatus:
    available: bool
    backend: str
    reason: str | None = None

def discover_worker(path: str | None = None) -> WorkerStatus:
    project_worker = Path(__file__).resolve().parents[2] / "native_worker" / "build" / "Release" / "qds_vulkan_worker.exe"
    executable = path or os.environ.get("QDS_VULKAN_WORKER") or shutil.which("qds_vulkan_worker")
    if not executable and project_worker.exists():
        executable = str(project_worker)
    if not executable:
        return WorkerStatus(False, "cpu", "worker_not_installed")
    try:
        result = subprocess.run([executable], capture_output=True, text=True, timeout=3, check=False)
        if result.returncode == 0 and '"status":"READY"' in result.stdout:
            return WorkerStatus(True, "vulkan")
        return WorkerStatus(False, "cpu", "vulkan_unavailable")
    except (OSError, subprocess.TimeoutExpired):
        return WorkerStatus(False, "cpu", "worker_probe_failed")
