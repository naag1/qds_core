"""QDS v1 authenticated control-plane API."""
import os
import tempfile
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.database import Alert, Sensor, User, get_db, init_db
from app.module1_aggregator.parser import parse_pcap_batches, parser_backend
from app.module3_explainer.explainer import Phase3Explainer
from app.queueing import enqueue_explanation
from app.schemas import FlowEvent, SensorStatus, TriageUpdate
from app.security import create_token, current_user, hash_password, require_role, verify_password
from app.services import DetectionService, audit, upsert_sensor
from app.settings import get_settings

settings, service, explainer = get_settings(), None, None
FLOW_EVENTS = Counter("qds_flow_events_total", "Accepted flow events")
ALERTS = Counter("qds_alerts_total", "Created alerts", ["severity"])
QUEUE_REJECTS = Counter("qds_explanation_queue_rejected_total", "Explanation jobs not queued")
SENSOR_DROPS = Gauge("qds_sensor_packet_drops", "Sensor reported packet drops", ["sensor_id"])

@asynccontextmanager
async def lifespan(_: FastAPI):
    global service, explainer
    if settings.environment == "production" and settings.jwt_secret == "change-me-before-production": raise RuntimeError("Configure QDS_JWT_SECRET")
    init_db()
    db = next(get_db())
    try:
        if not db.query(User).filter_by(username=settings.bootstrap_admin_username).first():
            db.add(User(username=settings.bootstrap_admin_username, password_hash=hash_password(settings.bootstrap_admin_password), role="admin")); db.commit()
    finally: db.close()
    service = DetectionService()
    explainer = Phase3Explainer()
    yield

app = FastAPI(title="QDS Network IDS", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.allowed_origins.split(",") if x.strip()], allow_credentials=True, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type", "X-Sensor-Token"])

def sensor_auth(x_sensor_token: str = Header(default="")):
    expected = os.environ.get("QDS_SENSOR_TOKEN")
    if not expected or x_sensor_token != expected: raise HTTPException(status_code=401, detail="Invalid sensor token")

def alert_view(alert: Alert) -> dict:
    verdict = alert.detection.get("analyst_verdict")
    if not verdict:
        verdict = "pending" if alert.explanation_status in {"queued", "running", "retry", "not_requested"} else "unavailable" if alert.explanation_status in {"unavailable", "not_queued"} else "review_required"
    return {"id": alert.id, "severity": alert.severity, "status": alert.status, "created_at": alert.created_at, "sensor_id": alert.sensor_id, "detection": alert.detection, "verdict": verdict, "explanation_status": alert.explanation_status, "explanation": alert.explanation}

@app.get("/healthz")
def healthz(): return {"status": "ok"}

@app.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1")); return {"status": "ready", "parser": parser_backend(), "model": service.manifest["package_version"] if service else None}

@app.get("/api/v1/ai/status")
def ai_status(_: User = Depends(current_user)):
    return explainer.status()

@app.post("/api/v1/ai/test")
def ai_test(_: User = Depends(require_role("admin", "analyst"))):
    result = explainer.generate_explanation({
        "flow_summary": "QDS AI connectivity check",
        "prediction": "BENIGN",
        "confidence": 0.99,
        "heuristic_flags": [],
        "is_anomaly": False,
        "flow_metrics": {"total_packets": 1, "total_bytes": 64, "flow_duration": 1.0},
    })
    if not result.get("success"):
        raise HTTPException(503, detail=result.get("error", "AI model did not return a response"))
    return {"success": True, "model": result.get("model"), "response_preview": result["explanation"][:400]}

@app.get("/metrics", response_class=PlainTextResponse)
def metrics(): return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

@app.post("/api/v1/auth/token")
def token(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter_by(username=form.username).first()
    if not user or not user.active or not verify_password(form.password, user.password_hash): raise HTTPException(401, "Invalid credentials")
    return {"access_token": create_token(user), "token_type": "bearer", "role": user.role}

@app.post("/api/v1/sensors/heartbeat", dependencies=[Depends(sensor_auth)])
def heartbeat(payload: SensorStatus, db: Session = Depends(get_db)):
    sensor = upsert_sensor(db, payload.model_dump()); SENSOR_DROPS.labels(sensor.id).set(sensor.packet_drops); db.commit(); return {"id": sensor.id, "status": sensor.status}

@app.post("/api/v1/sensors/{sensor_id}/flows", dependencies=[Depends(sensor_auth)])
def ingest_flow(sensor_id: str, flow: FlowEvent, db: Session = Depends(get_db)):
    if not db.get(Sensor, sensor_id): raise HTTPException(404, "Unknown sensor")
    alert = service.process(db, sensor_id, flow.model_dump())
    FLOW_EVENTS.inc()
    if alert:
        ALERTS.labels(alert.severity).inc()
    db.commit()
    if alert and not enqueue_explanation(alert.id):
        alert.explanation_status = "not_queued"
        QUEUE_REJECTS.inc()
        db.commit()
    return {"accepted": True, "alert_id": alert.id if alert else None}

@app.get("/api/v1/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, limit: int = Query(100, ge=1, le=500), _: User = Depends(current_user), db: Session = Depends(get_db)):
    query = db.query(Alert).order_by(Alert.created_at.desc())
    if status: query = query.filter(Alert.status == status)
    if severity: query = query.filter(Alert.severity == severity)
    return [alert_view(item) for item in query.limit(limit)]

@app.get("/api/v1/sensors")
def list_sensors(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return [
        {"id": sensor.id, "name": sensor.name, "platform": sensor.platform, "backend": sensor.backend,
         "status": sensor.status, "packet_drops": sensor.packet_drops, "last_seen_at": sensor.last_seen_at}
        for sensor in db.query(Sensor).order_by(Sensor.last_seen_at.desc()).all()
    ]

@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int, _: User = Depends(current_user), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    return {**alert_view(alert), "flow": alert.flow.features, "model_version": alert.model_version, "rule_version": alert.rule_version}

@app.post("/api/v1/alerts/{alert_id}/explanation")
def retry_explanation(alert_id: int, _: User = Depends(require_role("admin", "analyst")), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    alert.explanation_status = "queued"
    alert.explanation = None
    alert.detection = {key: value for key, value in alert.detection.items() if key != "analyst_verdict"}
    db.commit()
    if not enqueue_explanation(alert.id):
        alert.explanation_status = "not_queued"
        db.commit()
        raise HTTPException(503, "The explanation queue is unavailable or full")
    return {"id": alert.id, "explanation_status": alert.explanation_status}

@app.patch("/api/v1/alerts/{alert_id}/triage")
def triage(alert_id: int, update: TriageUpdate, user: User = Depends(require_role("admin", "analyst")), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert: raise HTTPException(404, "Alert not found")
    alert.status = update.status; audit(db, user.username, "alert.triage", str(alert_id), {"status": update.status}); db.commit(); return alert_view(alert)

@app.post("/api/v1/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...), _: User = Depends(require_role("admin", "analyst")), db: Session = Depends(get_db)):
    suffix = os.path.splitext(file.filename or "capture.pcap")[1].lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}: raise HTTPException(415, "Only PCAP formats are supported")
    path = None; total = alerts = 0; pending_explanations = []
    try:
        # Offline uploads do not originate from a live sensor.  Create the
        # internal source once so flow records retain the same foreign-key and
        # audit semantics as live ingestion.  Previously every parsed flow was
        # discarded unless an operator had created this implementation-detail
        # sensor by hand.
        if not db.get(Sensor, "pcap-upload"):
            upsert_sensor(db, {
                "id": "pcap-upload",
                "name": "PCAP upload",
                "platform": "linux",
                "backend": "cpu",
                "packet_drops": 0,
            })
        with tempfile.NamedTemporaryFile(prefix="qds_", suffix=suffix, delete=False) as target:
            path = target.name
            while chunk := await file.read(1024 * 1024):
                if target.tell() + len(chunk) > settings.max_upload_bytes: raise HTTPException(413, "Capture exceeds limit")
                target.write(chunk)
        for batch in parse_pcap_batches(path):
            for flow in batch:
                total += 1
                alert = service.process(db, "pcap-upload", flow)
                if alert:
                    alerts += 1
                    pending_explanations.append(alert.id)
        db.commit()
        for alert_id in pending_explanations:
            if not enqueue_explanation(alert_id):
                alert = db.get(Alert, alert_id)
                if alert:
                    alert.explanation_status = "not_queued"
                QUEUE_REJECTS.inc()
        db.commit()
        return {"flows": total, "alerts": alerts}
    finally:
        if path and os.path.exists(path): os.remove(path)
