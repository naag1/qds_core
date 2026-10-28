from app.module3_explainer.explainer import Phase3Explainer

def main():
    print("==================================================")
    print("      QDS PHASE 3 INTEGRATION TEST                ")
    print("==================================================")

    # Simulated Phase 2 telemetry output
    sample_phase2_alert = {
        "flow_summary": "86.128.100.24:2029 -> 192.168.1.2:135",
        "prediction": "BENIGN",
        "confidence": 0.9696,
        "heuristic_flags": [
            "HEURISTIC_PORT_SCAN_PROBE"
        ],
        "is_anomaly": True,
        "flow_metrics": {
            "total_packets": 4,
            "total_bytes": 240,
            "duration": "0.042s"
        }
    }

    print("[*] Input Phase 2 Detection Alert:")
    print(f"    Flow: {sample_phase2_alert['flow_summary']}")
    print(f"    ML Prediction: {sample_phase2_alert['prediction']} ({sample_phase2_alert['confidence']*100:.2f}%)")
    print(f"    Heuristic Flags: {sample_phase2_alert['heuristic_flags']}\n")

    print("[*] Dispatching to Phase 3 Explanation Engine (qwen2.5:3b)...")
    
    explainer = Phase3Explainer(model_name="qwen2.5:3b")
    response = explainer.generate_explanation(sample_phase2_alert)

    if response["success"]:
        print(f"[+] Report Generated Successfully in {response['eval_duration_sec']}s!")
        print("\n" + "="*20 + " GENERATED SOC REPORT " + "="*20)
        print(response["explanation"])
        print("="*60)
    else:
        print(f"[!] Phase 3 Processing Failed: {response['error']}")

if __name__ == "__main__":
    main()