"""Run as `python -m app.worker` to enrich stored alerts without blocking detection."""
import json
from redis import Redis
from app.database import Alert, SessionLocal
from app.module3_explainer.explainer import Phase3Explainer
from app.queueing import QUEUE
from app.settings import get_settings
def run() -> None:
    # BLPOP may wait for the full server-side timeout.  Give the socket a
    # margin beyond that wait so an idle queue is treated as an empty poll
    # rather than a fatal redis.exceptions.TimeoutError.
    client = Redis.from_url(
        get_settings().redis_url,
        socket_connect_timeout=5,
        socket_timeout=10,
    )
    explainer = Phase3Explainer()
    while True:
        item = client.blpop(QUEUE, timeout=5)
        if not item: continue
        with SessionLocal() as db:
            alert = db.get(Alert, json.loads(item[1])["alert_id"])
            if not alert or alert.explanation_status not in {"queued", "retry"}: continue
            alert.explanation_status = "running"; db.commit()
            flow = alert.flow.features
            payload = {**alert.detection, "flow_metrics": {k: flow.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "total_packets", "total_bytes", "flow_duration")}}
            result = explainer.generate_explanation(payload)
            if result.get("success"):
                verdict = result.get("verdict")
                alert.detection = {**alert.detection, "analyst_verdict": verdict or "review_required"}
                alert.explanation_status = "complete" if verdict else "review_required"
                alert.explanation = result.get("explanation")
            else:
                alert.detection = {**alert.detection, "analyst_verdict": "unavailable"}
                alert.explanation_status = "unavailable"
                alert.explanation = result.get("error", "AI explanation failed")
            db.commit()
if __name__ == "__main__": run()
