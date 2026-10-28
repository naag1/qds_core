"""Bounded Redis work queue; callers degrade safely when it is unavailable."""
import json
from redis import Redis
from app.settings import get_settings
QUEUE = "qds:explanations"
def enqueue_explanation(alert_id: int) -> bool:
    try:
        client = Redis.from_url(get_settings().redis_url, socket_connect_timeout=1, socket_timeout=1)
        if client.llen(QUEUE) >= get_settings().max_queue_depth: return False
        client.rpush(QUEUE, json.dumps({"alert_id": alert_id})); return True
    except Exception: return False
