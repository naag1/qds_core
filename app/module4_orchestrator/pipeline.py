

import time
import os
from typing import Dict, Any, List, Union
from app.module1_aggregator.parser import parse_pcap_batches
from app.module2_detector.inference import DetectorEngine
from app.module3_explainer.explainer import Phase3Explainer


class QDSPipeline:
    """Orchestrates end-to-end execution across Module 1, Module 2, and Module 3."""

    def __init__(
        self,
        onnx_model_path: str = "app/module2_detector/model.onnx",
        llm_model_name: str = "qwen2.5:3b"
        , inference_batch_size: int = 4096
    ):
        print("[*] Initializing QDS Core Pipeline...")
        self.detector = DetectorEngine(model_path=onnx_model_path)
        self.explainer = Phase3Explainer(model_name=llm_model_name)
        self.inference_batch_size = inference_batch_size
        print("[+] QDS Core Pipeline Initialized Successfully.")

    def process_flow_dict(self, flow_data: Dict[str, Any], generate_report: bool = True) -> Dict[str, Any]:
        """
        Processes a single flow dictionary feature vector through Module 2 and Module 3.
        """
        start_time = time.time()

        # Step 1: Run Hybrid ML + Heuristic Detection (Module 2)
        detection_result = self.detector.predict_flow(flow_data)

        # Step 2: Generate SOC Explanation if anomaly detected or explicitly requested
        soc_report = None
        explanation_meta = {}

        if generate_report and detection_result.get("is_anomaly", False):
            # Combine raw metrics into detection payload for LLM context
            detection_payload = {
                **detection_result,
                "flow_metrics": {
                    "total_packets": flow_data.get("total_packets", 0),
                    "total_bytes": flow_data.get("total_bytes", 0),
                    "duration": f"{flow_data.get('flow_duration', 0.0)}s",
                    "dst_port": flow_data.get("dst_port", 0)
                }
            }

            llm_response = self.explainer.generate_explanation(detection_payload)
            if llm_response.get("success"):
                soc_report = llm_response.get("explanation")
                explanation_meta = {
                    "eval_duration_sec": llm_response.get("eval_duration_sec"),
                    "eval_count": llm_response.get("eval_count")
                }
            else:
                soc_report = f"[!] SOC Report Generation Failed: {llm_response.get('error')}"

        total_latency = round(time.time() - start_time, 3)

        return {
            "pipeline_status": "SUCCESS",
            "total_latency_sec": total_latency,
            "flow_features": flow_data,
            "detection": detection_result,
            "soc_report": soc_report,
            "explanation_meta": explanation_meta
        }

    def process_pcap_file(self, pcap_path: str, generate_reports: bool = True) -> Dict[str, Any]:
        """
        Parses a .pcap file (Module 1), runs detection on all extracted flows (Module 2),
        and generates explanations for any detected anomalies (Module 3).
        """
        start_time = time.time()

        if not os.path.exists(pcap_path):
            return {
                "pipeline_status": "ERROR",
                "error": f"File not found: {pcap_path}"
            }

        # Step 1: Parse PCAP and extract aggregated flows (Module 1)
        flow_results = []
        anomalies_detected = 0
        total_flows = 0

        # Step 2 & 3: Run detection and explanation per flow
        for extracted_flows in parse_pcap_batches(pcap_path, self.inference_batch_size):
            detections = self.detector.predict_batch(extracted_flows)
            total_flows += len(extracted_flows)
            for flow, detection in zip(extracted_flows, detections):
            # Bulk jobs never synchronously invoke the LLM. Explanations can be
            # requested later for an individual alert.
                result = {
                    "pipeline_status": "SUCCESS",
                    "total_latency_sec": 0.0,
                    "flow_features": flow,
                    "detection": detection,
                    "soc_report": None,
                    "explanation_meta": {},
                }
                if detection.get("is_anomaly"):
                    anomalies_detected += 1
                flow_results.append(result)

        total_latency = round(time.time() - start_time, 3)

        return {
            "pipeline_status": "SUCCESS",
            "pcap_file": pcap_path,
            "total_flows_processed": total_flows,
            "total_anomalies_detected": anomalies_detected,
            "total_latency_sec": total_latency,
            "results": flow_results
        }
