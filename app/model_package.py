import hashlib, json
from pathlib import Path
from app.settings import get_settings

FEATURES = ["src_port", "dst_port", "protocol", "flow_duration", "total_packets", "total_bytes", "packet_length_mean", "packet_length_std", "bytes_per_second", "packets_per_second"]

def load_manifest() -> dict:
    path = Path(get_settings().model_manifest_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if data["feature_order"] != FEATURES: raise ValueError("model manifest feature order does not match runtime")
    model = path.parent / data["artifact"]
    if not model.exists(): raise ValueError("model artifact missing")
    if hashlib.sha256(model.read_bytes()).hexdigest() != data["sha256"]: raise ValueError("model artifact checksum mismatch")
    return data
