"""
Phase 4 Integration Test: Pipeline End-to-End Test
"""

from app.module4_orchestrator.pipeline import QDSPipeline

def main():
    print("==================================================")
    print("      QDS PHASE 4 PIPELINE INTEGRATION TEST       ")
    print("==================================================")

    pipeline = QDSPipeline()

    # Simulated Flow matching Flow.to_features() dictionary structure
    sample_flow = {
        "src_ip": "86.128.100.24",
        "dst_ip": "192.168.1.2",
        "src_port": 2029,
        "dst_port": 135,
        "protocol": 6,
        "flow_duration": 0.042,
        "total_packets": 3,
        "total_bytes": 240,
        "packet_length_mean": 80.0,
        "packet_length_std": 0.0,
        "bytes_per_second": 5714.29,
        "packets_per_second": 71.43
    }

    print("\n[*] Input Flow Telemetry:")
    print(f"    {sample_flow['src_ip']}:{sample_flow['src_port']} -> {sample_flow['dst_ip']}:{sample_flow['dst_port']}")
    print(f"    Packets: {sample_flow['total_packets']} | Duration: {sample_flow['flow_duration']}s\n")

    print("[*] Executing Unified Pipeline...")
    response = pipeline.process_flow_dict(sample_flow, generate_report=True)

    print(f"\n[+] Pipeline Completed in {response['total_latency_sec']}s")
    print("\n--- Detection Results ---")
    print(f"ML Prediction:   {response['detection']['prediction']}")
    print(f"Confidence:      {response['detection']['confidence']}")
    print(f"Heuristic Flags: {response['detection']['heuristic_flags']}")
    print(f"Is Anomaly:      {response['detection']['is_anomaly']}")

    if response.get("soc_report"):
        print("\n==================== SOC REPORT OUTPUT ====================")
        print(response["soc_report"])
        print("===========================================================")

if __name__ == "__main__":
    main()