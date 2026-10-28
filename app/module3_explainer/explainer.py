import json
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from app.module3_explainer.prompt_templates import SOC_SYSTEM_PROMPT, build_user_prompt
from app.module3_explainer.verdict import extract_verdict, normalize_report_classification


class Phase3Explainer:
    """Phase 3 Security Reasoning and Explanation Engine using Ollama."""

    def __init__(
        self,
        model_name: str | None = None,
        ollama_host: str | None = None,
    ):
        self.model_name = model_name or os.getenv("QDS_OLLAMA_MODEL", "qwen2.5:3b")
        self.host = (ollama_host or os.getenv("QDS_OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.generate_url = f"{self.host}/api/generate"

    def status(self) -> Dict[str, Any]:
        """Report Ollama connectivity and whether the configured model is installed."""
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as response:
                payload = json.loads(response.read().decode("utf-8"))
            models = [item.get("name", "") for item in payload.get("models", [])]
            installed = any(name == self.model_name or name.startswith(self.model_name + ":") for name in models)
            return {
                "reachable": True,
                "model": self.model_name,
                "model_available": installed,
                "models": models,
                "error": None if installed else f"Model {self.model_name} is not installed in Ollama.",
            }
        except Exception as exc:
            return {
                "reachable": False,
                "model": self.model_name,
                "model_available": False,
                "models": [],
                "error": f"Cannot reach Ollama at {self.host}: {exc}",
            }

    def is_service_ready(self) -> bool:
        state = self.status()
        return state["reachable"] and state["model_available"]

    def generate_explanation(self, phase2_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes Phase 2 telemetry and generates a structured explanation report.
        """
        service_state = self.status()
        if not service_state["reachable"] or not service_state["model_available"]:
            return {
                "success": False,
                "error": service_state["error"],
            }

        # Do not pass packet payloads, arbitrary user text, credentials, or model
        # instructions downstream. This is a strict security telemetry allow-list.
        safe = {
            "flow_summary": str(phase2_data.get("flow_summary", "unknown"))[:256],
            "prediction": str(phase2_data.get("prediction", "UNKNOWN"))[:64],
            "confidence": float(phase2_data.get("confidence", 0)),
            "heuristic_flags": [str(x)[:64] for x in phase2_data.get("heuristic_flags", [])[:20]],
            "is_anomaly": bool(phase2_data.get("is_anomaly", False)),
            "flow_metrics": {key: phase2_data.get("flow_metrics", {}).get(key) for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "total_packets", "total_bytes", "flow_duration")},
        }
        user_prompt = build_user_prompt(safe)

        payload = {
            "model": self.model_name,
            "system": SOC_SYSTEM_PROMPT,
            "prompt": user_prompt,
            "stream": False,
            "options": {
                "num_ctx": 2048,     # VRAM-friendly context limit for 6GB card
                "num_predict": 768,
                "temperature": 0.198,  # Low temperature for stable deterministic security reports
                "top_p": 0.911
            }
        }

        try:
            req = urllib.request.Request(
                self.generate_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=240) as response:
                if response.status == 200:
                    result = json.loads(response.read().decode("utf-8"))
                    explanation_text = result.get("response", "").strip()[:12_000]
                    verdict = extract_verdict(explanation_text)
                    explanation_text = normalize_report_classification(explanation_text, verdict)
                    
                    return {
                        "success": True,
                        "model": self.model_name,
                        "explanation": explanation_text,
                        "verdict": verdict,
                        "eval_count": result.get("eval_count", 0),
                        "eval_duration_sec": round(result.get("eval_duration", 0) / 1e9, 2)
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Ollama returned HTTP status {response.status}"
                    }

        except urllib.error.URLError as e:
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Unexpected error: {str(e)}"}
