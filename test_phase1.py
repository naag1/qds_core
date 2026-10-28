import os
import json
from app.module1_aggregator.parser import parse_pcap

def verify():
    # place test .pcap file in samples folder for testing
    sample_pcap_path = "app/samples/tfp_capture.pcapng"

    if not os.path.exists(sample_pcap_path):
        print(f"[!] Please place a test PCAP file at: {sample_pcap_path}")
        return

    print(f"[*] Parsing PCAP file: {sample_pcap_path}...")
    aggregated_flows = parse_pcap(sample_pcap_path)
    
    print(f"[+] Total Flows Extracted: {len(aggregated_flows)}\n")
    print("[+] Sample Aggregated Flow Output:")
    if aggregated_flows:
        print(json.dumps(aggregated_flows[0], indent=2))

if __name__ == "__main__":
    verify()