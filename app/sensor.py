"""Passive live-capture sensor with bounded buffering and API delivery.

Install the optional `pcapy-ng` extra on Linux or Windows with Npcap installed.
Run with administrator/root capture permission only; this service never injects
or blocks packets.
"""
import argparse, os, queue, threading, time
from collections import defaultdict
import requests
from app.module1_aggregator.flow_features import Flow
from app.module1_aggregator.parser import decode_packet

class FlowTable:
    def __init__(self, timeout: float = 60.0, max_lifetime: float = 300.0): self.timeout, self.max_lifetime, self.flows = timeout, max_lifetime, {}
    def add(self, key, flow: Flow): self.flows[key] = flow
    def expired(self, now: float):
        stale = [key for key, flow in self.flows.items() if now - flow.last_time >= self.timeout or now - flow.start_time >= self.max_lifetime]
        return [self.flows.pop(key).to_features() for key in stale]

class Sensor:
    def __init__(self, api: str, token: str, sensor_id: str, queue_size: int = 8192):
        self.api, self.token, self.sensor_id = api.rstrip("/"), token, sensor_id
        self.q, self.drops, self.stop = queue.Queue(maxsize=queue_size), 0, threading.Event()
    def publish(self, flow: dict):
        try: self.q.put_nowait(flow)
        except queue.Full: self.drops += 1
    def sender(self):
        headers = {"X-Sensor-Token": self.token}
        while not self.stop.is_set():
            try: flow = self.q.get(timeout=1)
            except queue.Empty: continue
            try: requests.post(f"{self.api}/api/v1/sensors/{self.sensor_id}/flows", json=flow, headers=headers, timeout=3).raise_for_status()
            except requests.RequestException: self.drops += 1 # bounded, deliberate drop rather than unbounded retry
    def heartbeat(self, name: str, platform: str):
        requests.post(f"{self.api}/api/v1/sensors/heartbeat", json={"id": self.sensor_id, "name": name, "platform": platform, "backend": "cpu", "packet_drops": self.drops}, headers={"X-Sensor-Token": self.token}, timeout=3).raise_for_status()

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--interface", required=True); parser.add_argument("--api", required=True); parser.add_argument("--sensor-id", required=True); parser.add_argument("--name", default="qds-sensor")
    args = parser.parse_args(); token = os.environ["QDS_SENSOR_TOKEN"]
    try: import pcapy
    except ImportError as exc: raise SystemExit("Install pcapy-ng and platform capture drivers (libpcap/Npcap): " + str(exc))
    import platform
    sensor = Sensor(args.api, token, args.sensor_id); sensor.heartbeat(args.name, "windows" if platform.system() == "Windows" else "linux")
    threading.Thread(target=sensor.sender, daemon=True).start()
    capture, flows, last_heartbeat = pcapy.open_live(args.interface, 65535, 1, 100), FlowTable(), time.monotonic()
    while True:
        header, packet = capture.next()
        now = time.time()
        if header:
            decoded = decode_packet(packet)
            if decoded:
                key, fields = decoded
                if key not in flows.flows: flows.add(key, Flow(start_time=now, **fields))
                flows.flows[key].add_packet(len(packet), now)
        for completed in flows.expired(now): sensor.publish(completed)
        if time.monotonic() - last_heartbeat >= 15:
            try: sensor.heartbeat(args.name, "windows" if platform.system() == "Windows" else "linux")
            except requests.RequestException: pass
            last_heartbeat = time.monotonic()

if __name__ == "__main__": main()
