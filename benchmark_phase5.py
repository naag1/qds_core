"""Repeatable Phase 5 backend baseline benchmark."""
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "app" / "samples" / "tfp_capture.pcapng"
WORKER = ROOT / "native_worker" / "build" / "Release" / "qds_vulkan_worker.exe"


def timed(fn, repetitions):
    values = []
    result = None
    for _ in range(repetitions):
        started = time.perf_counter()
        result = fn()
        values.append(time.perf_counter() - started)
    return result, values


def main():
    from app.module1_aggregator.parser import parse_pcap, parser_backend
    from app.module4_orchestrator.pipeline import QDSPipeline

    repetitions = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    flows, parse_times = timed(lambda: parse_pcap(str(SAMPLE)), repetitions)
    pipeline = QDSPipeline(inference_batch_size=4096)
    report, pipeline_times = timed(
        lambda: pipeline.process_pcap_file(str(SAMPLE), generate_reports=False), repetitions
    )

    worker = {"status": "UNAVAILABLE"}
    if WORKER.exists():
        probe = subprocess.run([str(WORKER)], capture_output=True, text=True, timeout=5)
        try:
            worker = json.loads(probe.stdout)
        except json.JSONDecodeError:
            worker = {"status": "ERROR", "stderr": probe.stderr.strip()}

    packets_per_second = None
    if parse_times and SAMPLE.stat().st_size:
        packets_per_second = round(SAMPLE.stat().st_size / statistics.mean(parse_times), 2)

    output = {
        "backend": parser_backend(),
        "worker": worker,
        "capture": str(SAMPLE),
        "capture_bytes": SAMPLE.stat().st_size,
        "flows": len(flows),
        "anomalies": report.get("total_anomalies_detected"),
        "parse_seconds": {
            "min": round(min(parse_times), 6),
            "mean": round(statistics.mean(parse_times), 6),
            "max": round(max(parse_times), 6),
        },
        "pipeline_seconds": {
            "min": round(min(pipeline_times), 6),
            "mean": round(statistics.mean(pipeline_times), 6),
            "max": round(max(pipeline_times), 6),
        },
        "capture_bytes_per_second": packets_per_second,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
