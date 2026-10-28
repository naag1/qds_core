import os
import numpy as np
import onnxruntime as ort
from typing import Dict, Any, List, Tuple

class DetectorEngine:
    def __init__(self, model_path: str = "app/module2_detector/model.onnx"):
        self.model_path = model_path
        self.session = None
        self.input_name = None
        self.output_name = None
        self.label_mapping = {
            0: "BENIGN",
            1: "DoS/DDoS",
            2: "PortScan",
            3: "Botnet",
            4: "Infiltration"
        }
        
        if os.path.exists(self.model_path):
            self._load_model()
        else:
            print(f"[!] Warning: ONNX model file not found at '{self.model_path}'. Running in dummy/fallback mode.")

    def _load_model(self):
        """Initialize ONNX Runtime Session."""
        self.session = ort.InferenceSession(self.model_path, providers=['CPUExecutionProvider'])
        self.input_name = self.session.get_inputs()[0].name
        self.output_name = self.session.get_outputs()[0].name
        print(f"[+] Loaded ONNX Model successfully from {self.model_path}")

    def extract_feature_vector(self, flow: Dict[str, Any]) -> List[float]:
        """Extracts numerical features matching the model's training schema."""
        return [
            float(flow.get("src_port", 0)),
            float(flow.get("dst_port", 0)),
            float(flow.get("protocol", 0)),
            float(flow.get("flow_duration", 0.0)),
            float(flow.get("total_packets", 0)),
            float(flow.get("total_bytes", 0)),
            float(flow.get("packet_length_mean", 0.0)),
            float(flow.get("packet_length_std", 0.0)),
            float(flow.get("bytes_per_second", 0.0)),
            float(flow.get("packets_per_second", 0.0))
        ]

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Runs single-flow inference through both heuristics and ONNX model."""
        # 1. Rule checks
        from app.module2_detector.rules import evaluate_heuristics
        heuristic_alerts = evaluate_heuristics(flow)
        
        # 2. ML Inference
        predicted_class = "BENIGN"
        confidence = 0.0
        
        if self.session is not None:
            features = np.array([self.extract_feature_vector(flow)], dtype=np.float32)
            outputs = self.session.run(None, {self.input_name: features})
            
            # Extract predicted label and probabilities if present
            raw_pred = int(outputs[0][0])
            predicted_class = self.label_mapping.get(raw_pred, f"UNKNOWN_{raw_pred}")
            
            if len(outputs) > 1 and isinstance(outputs[1], list):
                # Probabilities array
                prob_dict = outputs[1][0]
                confidence = round(float(prob_dict.get(raw_pred, 0.0)), 4)
            else:
                confidence = 0.95 if predicted_class != "BENIGN" else 0.99
        else:
            # Fallback mock prediction when model.onnx is missing during initial setup
            if heuristic_alerts:
                predicted_class = "SUSPICIOUS_HEURISTIC"
                confidence = 0.85
        
        return {
            "flow_summary": f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}",
            "prediction": predicted_class,
            "confidence": confidence,
            "heuristic_flags": heuristic_alerts,
            "is_anomaly": predicted_class != "BENIGN" or len(heuristic_alerts) > 0
        }

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict a batch while preserving the single-flow response contract."""
        if not flows:
            return []
        from app.module2_detector.rules import evaluate_heuristics
        alerts = [evaluate_heuristics(flow) for flow in flows]
        if self.session is None:
            return [self.predict_flow(flow) for flow in flows]
        features = np.asarray([self.extract_feature_vector(flow) for flow in flows], dtype=np.float32)
        outputs = self.session.run(None, {self.input_name: features})
        labels = outputs[0]
        probabilities = outputs[1] if len(outputs) > 1 else None
        results = []
        for index, flow in enumerate(flows):
            raw_pred = int(labels[index])
            prediction = self.label_mapping.get(raw_pred, f"UNKNOWN_{raw_pred}")
            confidence = 0.95 if prediction != "BENIGN" else 0.99
            if isinstance(probabilities, list) and index < len(probabilities):
                confidence = round(float(probabilities[index].get(raw_pred, confidence)), 4)
            results.append({
                "flow_summary": f"{flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']}",
                "prediction": prediction,
                "confidence": confidence,
                "heuristic_flags": alerts[index],
                "is_anomaly": prediction != "BENIGN" or bool(alerts[index]),
            })
        return results
