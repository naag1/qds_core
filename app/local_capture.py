"""Loopback control service for starting and stopping Windows Packet Monitor."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt
import requests
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.module1_aggregator.parser import parse_pcap_batches
from app.settings import get_settings

settings = get_settings()
app = FastAPI(title="QDS Windows Capture Control", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

_lock = threading.Lock()
_capture: dict[str, Any] = {"active": False, "started_at": None, "etl_path": None, "work_dir": None}
SENSOR_ID = "windows-live"
API_BASE = os.getenv("QDS_LOCAL_API", "http://localhost:8000").rstrip("/")


def authorize(authorization: str = Header(default="")) -> dict[str, Any]:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Sign in to the QDS dashboard first")
    try:
        claims = jwt.decode(authorization[7:], settings.jwt_secret, algorithms=["HS256"])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(401, "Dashboard session expired; sign in again") from exc
    if claims.get("role") not in {"admin", "analyst"}:
        raise HTTPException(403, "An admin or analyst role is required to control capture")
    return claims


def _pktmon() -> str:
    path = shutil.which("pktmon")
    if not path:
        raise HTTPException(503, "Windows Packet Monitor (pktmon) was not found")
    return path


def _run(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "platform": "windows",
        "capture_active": _capture["active"],
        "pktmon_found": bool(shutil.which("pktmon")),
    }


@app.post("/api/session/start")
def start_capture(_: dict[str, Any] = Depends(authorize)) -> dict[str, Any]:
    with _lock:
        if _capture["active"]:
            raise HTTPException(409, "A live capture is already running")
        pktmon = _pktmon()
        work_dir = tempfile.mkdtemp(prefix="qds_capture_")
        etl_path = str(Path(work_dir) / "capture.etl")
        result = _run([
            pktmon, "start", "--capture", "--comp", "nics", "--pkt-size", "128",
            "--file-size", "64", "--log-mode", "circular", "--file-name", etl_path,
        ])
        if result.returncode != 0:
            shutil.rmtree(work_dir, ignore_errors=True)
            detail = (result.stderr or result.stdout or "Packet Monitor could not start").strip()
            if "access is denied" in detail.lower():
                detail = "Packet Monitor needs Administrator rights. Close this helper and restart it from the elevated PowerShell window."
            raise HTTPException(503, detail)
        _capture.update(active=True, started_at=datetime.now(timezone.utc), etl_path=etl_path, work_dir=work_dir)
        return {"status": "capturing", "started_at": _capture["started_at"]}


@app.post("/api/session/stop")
def stop_capture(_: dict[str, Any] = Depends(authorize)) -> dict[str, Any]:
    with _lock:
        if not _capture["active"]:
            raise HTTPException(409, "No live capture is running")
        pktmon = _pktmon()
        etl_path = _capture["etl_path"]
        work_dir = _capture["work_dir"]
        pcap_path = str(Path(work_dir) / "capture.pcapng")
        try:
            stopped = _run([pktmon, "stop"])
            if stopped.returncode != 0:
                raise HTTPException(503, (stopped.stderr or stopped.stdout or "Could not stop Packet Monitor").strip())
            converted = _run([pktmon, "etl2pcap", etl_path, "--out", pcap_path], timeout=60)
            if converted.returncode != 0 or not Path(pcap_path).exists():
                raise HTTPException(502, (converted.stderr or converted.stdout or "Could not convert capture to PCAPNG").strip())

            headers = {"X-Sensor-Token": settings.sensor_token}
            heartbeat = requests.post(
                f"{API_BASE}/api/v1/sensors/heartbeat",
                json={"id": SENSOR_ID, "name": "Windows live capture", "platform": "windows", "backend": "cpu", "packet_drops": 0},
                headers=headers, timeout=10,
            )
            heartbeat.raise_for_status()
            flow_count = alert_count = 0
            with requests.Session() as session:
                for batch in parse_pcap_batches(pcap_path):
                    for flow in batch:
                        response = session.post(
                            f"{API_BASE}/api/v1/sensors/{SENSOR_ID}/flows",
                            json=flow, headers=headers, timeout=10,
                        )
                        response.raise_for_status()
                        flow_count += 1
                        if response.json().get("alert_id") is not None:
                            alert_count += 1
            return {"status": "complete", "flows": flow_count, "alerts": alert_count}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(502, f"Capture was stopped but could not be analyzed: {exc}") from exc
        finally:
            _capture.update(active=False, started_at=None, etl_path=None, work_dir=None)
            shutil.rmtree(work_dir, ignore_errors=True)
