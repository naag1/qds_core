import os
import json
from app.module1_aggregator.parser import parse_pcap
from app.module2_detector.inference import DetectorEngine

def run_pipeline_test():
    sample_pcap = "app/samples/tfp_capture.pcapng"
    
    if not os.path.exists(sample_pcap):
        print(f"[!] Please place a test PCAP file at: {sample_pcap}")
        return

    print(f"[*] Step 1: Parsing PCAP file ({sample_pcap})...")
    flows = parse_pcap(sample_pcap)
    print(f"[+] Extracted {len(flows)} statistical flows.\n")

    print("[*] Step 2: Initializing Detection Engine...")
    detector = DetectorEngine()

    print("[*] Step 3: Running Heuristics & ML Inference...")
    detected_threats = []
    
    for flow in flows:
        result = detector.predict_flow(flow)
        if result["is_anomaly"]:
            detected_threats.append(result)

    print(f"\n[+] Pipeline Execution Complete!")
    print(f"[+] Total Flows Scanned: {len(flows)}")
    print(f"[+] Anomalies / Threats Detected: {len(detected_threats)}\n")

    if detected_threats:
        print("[+] Sample Threat Detection Output:")
        print(json.dumps(detected_threats[0], indent=2))
    else:
        print("[+] All flows classified as BENIGN with no heuristic flags.")

if __name__ == "__main__":
    run_pipeline_test()