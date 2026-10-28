import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any

# Target Models: Comparing Qwen 3B vs 7B
MODELS = [
    "qwen2.5:3b",
    "qwen2.5:7b"
]

BENCHMARK_PAYLOAD = {
    "flow_summary": "86.128.100.24:2029 -> 192.168.1.2:135",
    "prediction": "BENIGN",
    "confidence": 0.9696,
    "heuristic_flags": ["HEURISTIC_PORT_SCAN_PROBE"],
    "is_anomaly": True,
    "metrics": {
        "flow_duration_ms": 42,
        "total_packets": 4,
        "total_bytes": 240,
        "dst_port": 135
    }
}

SYSTEM_PROMPT = """You are a Level 3 SOC Analyst. Analyze network anomaly alerts and generate a structured incident report.
You must adhere strictly to these 3 markdown sections:
### 1. Attack Overview
### 2. Technical Feature Analysis
### 3. Immediate Mitigation Steps

Explain why the flow is suspicious even if the ML prediction indicates BENIGN."""

def generate_prompt(data: Dict[str, Any]) -> str:
    return f"""Analyze this detection alert:
- Flow: {data['flow_summary']}
- ML Prediction: {data['prediction']} ({data['confidence']*100:.1f}% confidence)
- Heuristic Flags: {', '.join(data['heuristic_flags'])}
- Protocol Context: Target Port {data['metrics']['dst_port']}, {data['metrics']['total_packets']} packets, {data['metrics']['total_bytes']} bytes over {data['metrics']['flow_duration_ms']}ms.

Provide your SOC analysis formatted strictly according to system instructions."""

def run_model_benchmark(model_name: str, host: str = "http://localhost:11434") -> Dict[str, Any]:
    url = f"{host.rstrip('/')}/api/generate"
    prompt = generate_prompt(BENCHMARK_PAYLOAD)
    
    payload = {
        "model": model_name,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": True,
        "options": {
            "num_predict": -1,  # -1 = Unlimited token prediction (stops natural finish)
            "num_ctx": 2048,    # Restrict context window to fit comfortably in 6GB VRAM
            "num_gpu": 99,      # Force full layer offloading to GPU
            "temperature": 0.2,
            "top_p": 0.9
        }
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    full_response = ""
    token_count = 0
    start_time = time.time()
    first_token_time = None

    try:
        with urllib.request.urlopen(req, timeout=180) as response:
            for line in response:
                if line:
                    chunk = json.loads(line.decode("utf-8"))
                    text = chunk.get("response", "")
                    
                    if text:
                        if first_token_time is None:
                            first_token_time = time.time() - start_time
                        full_response += text
                        token_count += 1
                        
                    if chunk.get("done", False):
                        eval_count = chunk.get("eval_count", token_count)
                        eval_duration = chunk.get("eval_duration", 1) / 1e9
                        tokens_per_sec = eval_count / eval_duration if eval_duration > 0 else 0
                        break

    except Exception as e:
        return {"error": str(e)}

    total_time = time.time() - start_time

    # Verification Metrics
    has_sec1 = "### 1. Attack Overview" in full_response or "1. Attack Overview" in full_response
    has_sec2 = "### 2. Technical Feature Analysis" in full_response or "2. Technical Feature Analysis" in full_response
    has_sec3 = "### 3. Immediate Mitigation Steps" in full_response or "3. Immediate Mitigation Steps" in full_response
    structure_score = sum([has_sec1, has_sec2, has_sec3])

    # Deep Technical Reasoning Check (7-point verification)
    lower_res = full_response.lower()
    keywords = {
        "port_135": "135" in lower_res or "rpc" in lower_res,
        "external_ip": "86.128" in lower_res or "external" in lower_res or "wan" in lower_res,
        "reconnaissance": "reconnaissance" in lower_res or "scan" in lower_res or "probe" in lower_res,
        "ml_conflict": "benign" in lower_res and ("low" in lower_res or "volume" in lower_res or "packet" in lower_res),
        "false_positive_awareness": "false positive" in lower_res or "discrepancy" in lower_res or "conflict" in lower_res,
        "vulnerability_context": "epmap" in lower_res or "execution" in lower_res or "exploit" in lower_res or "windows" in lower_res,
        "mitigation_action": "block" in lower_res or "firewall" in lower_res or "rule" in lower_res
    }
    reasoning_score = sum(keywords.values())

    return {
        "model": model_name,
        "latency_sec": round(total_time, 2),
        "ttft_sec": round(first_token_time or total_time, 2),
        "tokens_per_sec": round(tokens_per_sec, 2),
        "total_tokens": token_count,
        "structure_score": f"{structure_score}/3",
        "reasoning_score": f"{reasoning_score}/7",
        "raw_output": full_response
    }

def main():
    print("==========================================================================")
    print("      QDS PHASE 3 BENCHMARK: UNTRUNCATED REASONING (Qwen 3B vs 7B)        ")
    print("==========================================================================")
    
    results = []

    for model in MODELS:
        print(f"\n[*] Benchmarking Model: {model} ...")
        res = run_model_benchmark(model)
        
        if "error" in res:
            print(f"[!] Error benchmarking {model}: {res['error']}")
            continue

        results.append(res)
        
        print(f"    ├─ Total Latency:     {res['latency_sec']}s")
        print(f"    ├─ Time To 1st Token:  {res['ttft_sec']}s")
        print(f"    ├─ Generation Speed:  {res['tokens_per_sec']} tokens/sec")
        print(f"    ├─ Tokens Generated:  {res['total_tokens']}")
        print(f"    ├─ Structure Score:   {res['structure_score']}")
        print(f"    └─ Reasoning Score:   {res['reasoning_score']}")
        
        print("\n" + "="*40 + f" COMPLETE OUTPUT [{model}] " + "="*40)
        print(res['raw_output'])
        print("="*100 + "\n")

    print("\n" + "="*80)
    print("                            FINAL BENCHMARK SUMMARY                       ")
    print("="*80)
    print(f"{'Model':<15} | {'Latency(s)':<10} | {'Speed(tok/s)':<12} | {'Tokens':<8} | {'Structure':<10} | {'Reasoning':<10}")
    print("-" * 80)
    for r in results:
        print(f"{r['model']:<15} | {r['latency_sec']:<10} | {r['tokens_per_sec']:<12} | {r['total_tokens']:<8} | {r['structure_score']:<10} | {r['reasoning_score']:<10}")
    print("="*80)

if __name__ == "__main__":
    main()