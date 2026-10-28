from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
from app.database import Alert, AuditEvent, FlowRecord, Sensor
from app.module2_detector.inference import DetectorEngine
from app.module2_detector.rules import evaluate_rules, rule_set
from app.model_package import load_manifest

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def severity_for(detection: dict, rules: list[dict]) -> str:
    severity = max((r["severity"] for r in rules), key=lambda item: SEVERITY_ORDER[item], default="low")
    if detection["prediction"] != "BENIGN" and detection["confidence"] >= .90:
        severity = max(severity, "high", key=lambda item: SEVERITY_ORDER[item])
    return severity

class DetectionService:
    def __init__(self):
        self.manifest = load_manifest()
        self.detector = DetectorEngine(model_path=str(Path("app/module2_detector") / self.manifest["artifact"]))

    def process(self, db: Session, sensor_id: str, flow: dict) -> Alert | None:
        flow["src_ip"], flow["dst_ip"] = str(flow["src_ip"]), str(flow["dst_ip"])
        duration = max(float(flow["flow_duration"]), .000001)
        flow["bytes_per_second"] = round(flow["total_bytes"] / duration, 2)
        flow["packets_per_second"] = round(flow["total_packets"] / duration, 2)
        detection = self.detector.predict_flow(flow)
        rules = evaluate_rules(flow)
        detection["rule_evidence"] = rules
        record = FlowRecord(sensor_id=sensor_id, observed_at=flow.pop("observed_at", None) or datetime.now(timezone.utc), features=flow, model_version=self.manifest["package_version"])
        db.add(record); db.flush()
        if not detection["is_anomaly"]: return None
        alert = Alert(flow_id=record.id, sensor_id=sensor_id, severity=severity_for(detection, rules), detection=detection, model_version=self.manifest["package_version"], rule_version=rule_set()["version"], explanation_status="queued")
        db.add(alert); db.flush()
        return alert

def audit(db: Session, actor: str, action: str, target: str, detail: dict | None = None) -> None:
    db.add(AuditEvent(actor=actor, action=action, target=target, detail=detail or {}))

def upsert_sensor(db: Session, payload: dict) -> Sensor:
    sensor = db.get(Sensor, payload["id"])
    if not sensor: sensor = Sensor(**payload); db.add(sensor)
    else:
        for key, value in payload.items(): setattr(sensor, key, value)
        sensor.status = "online"; sensor.last_seen_at = datetime.now(timezone.utc)
    db.flush(); return sensor
