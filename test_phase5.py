"""Phase 5 verification: Vulkan worker readiness and backend pipeline."""

import json
import os
import subprocess
import sys
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "app" / "samples" / "tfp_capture.pcapng"
WORKER = ROOT / "native_worker" / "build" / "Release" / "qds_vulkan_worker.exe"
SHADER = ROOT / "native_worker" / "shaders" / "packet_features.comp.spv"


def check(label, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}{(': ' + detail) if detail else ''}")
    return condition


def main():
    print("=" * 64)
    print(" QDS PHASE 5: VULKAN + BACKEND PROCESSING VERIFICATION")
    print("=" * 64)

    results = []
    results.append(check("Vulkan worker exists", WORKER.exists(), str(WORKER)))
    results.append(check("Compiled compute shader exists", SHADER.exists(), str(SHADER)))
    validator = shutil.which("spirv-val") or str(Path(r"C:\VulkanSDK\1.4.363.0\Bin\spirv-val.exe"))
    if SHADER.exists() and Path(validator).exists():
        validated = subprocess.run([validator, str(SHADER)], capture_output=True, text=True)
        results.append(check("SPIR-V validation", validated.returncode == 0, validated.stderr.strip()))

    worker_payload = None
    if WORKER.exists():
        try:
            env = os.environ.copy()
            env["VULKAN_SDK"] = env.get("VULKAN_SDK", r"C:\VulkanSDK\1.4.363.0")
            completed = subprocess.run(
                [str(WORKER)], capture_output=True, text=True, timeout=5, env=env
            )
            output = completed.stdout.strip()
            worker_payload = json.loads(output) if output else {}
            results.append(check(
                "Vulkan worker probe",
                completed.returncode == 0 and worker_payload.get("backend") == "vulkan",
                output or completed.stderr.strip(),
            ))
        except Exception as exc:
            results.append(check("Vulkan worker probe", False, str(exc)))

    try:
        from app.module1_aggregator.parser import parse_pcap, parser_backend
        from app.module4_orchestrator.pipeline import QDSPipeline

        backend = parser_backend()
        results.append(check(
            "Python reports truthful backend state",
            backend.get("gpu_available") is backend.get("worker_process_pcap"),
            str(backend),
        ))
        results.append(check("Sample PCAP exists", SAMPLE.exists(), str(SAMPLE)))

        if SAMPLE.exists():
            flows = parse_pcap(str(SAMPLE))
            results.append(check("PCAP parsing", len(flows) > 0, f"{len(flows)} flows"))

            pipeline = QDSPipeline(inference_batch_size=64)
            report = pipeline.process_pcap_file(str(SAMPLE), generate_reports=False)
            results.append(check(
                "Batched detection pipeline",
                report.get("pipeline_status") == "SUCCESS" and report.get("total_flows_processed") == len(flows),
                f"{report.get('total_flows_processed', 0)} flows, {report.get('total_anomalies_detected', 0)} anomalies, {report.get('total_latency_sec')}s",
            ))
    except Exception as exc:
        results.append(check("Python backend pipeline", False, repr(exc)))

    print("=" * 64)
    passed = sum(results)
    print(f"Result: {passed}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
