import dpkt
import socket
from typing import List, Dict, Any, Iterator
from app.module1_aggregator.flow_features import Flow
from app.module1_aggregator.gpu_worker import discover_worker
from app.module1_aggregator.worker_client import VulkanWorkerClient

def decode_packet(buf: bytes) -> tuple[tuple, dict] | None:
    """Decode one Ethernet IPv4/IPv6 TCP/UDP frame for live or offline capture."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)): return None
        src_ip, dst_ip, protocol = inet_to_str(ip.src), inet_to_str(ip.dst), ip.nxt if isinstance(ip, dpkt.ip6.IP6) else ip.p
        src_port = dst_port = 0
        if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)): src_port, dst_port = ip.data.sport, ip.data.dport
        key = tuple(sorted(((src_ip, src_port), (dst_ip, dst_port)))) + (protocol,)
        return key, {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol}
    except Exception: return None

def inet_to_str(inet) -> str:
    """Convert inet network address to human-readable IP string."""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def parse_pcap(pcap_file_path: str) -> List[Dict[str, Any]]:
    """Reads .pcap, .cap, and .pcapng files using dpkt and aggregates flows."""
    flows: Dict[tuple, Flow] = {}

    with open(pcap_file_path, 'rb') as f:
        # Try standard pcap / cap format first
        try:
            pcap = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.dpkt.NeedData):
            # Fallback to pcapng format
            f.seek(0)
            try:
                pcap = dpkt.pcapng.Reader(f)
            except Exception as e:
                raise ValueError(f"Unsupported packet capture format or corrupted file: {e}")

        for ts, buf in pcap:
            decoded = decode_packet(buf)
            if not decoded: continue
            flow_key, fields = decoded

            if flow_key not in flows:
                flows[flow_key] = Flow(start_time=ts, **fields)

            flows[flow_key].add_packet(len(buf), ts)

    return [flow.to_features() for flow in flows.values()]

def parse_pcap_batches(pcap_file_path: str, batch_size: int = 4096) -> Iterator[List[Dict[str, Any]]]:
    """Yield bounded flow batches for downstream inference/result sinks."""
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    flows = parse_pcap(pcap_file_path)
    for offset in range(0, len(flows), batch_size):
        yield flows[offset:offset + batch_size]

def parser_backend() -> Dict[str, Any]:
    status = discover_worker()
    capabilities = VulkanWorkerClient().capabilities() if status.available else {}
    process_ready = bool(status.available and capabilities.get("process_pcap") is True)
    return {
        "backend": "vulkan" if process_ready else "cpu",
        "ready": process_ready,
        "gpu_available": process_ready,
        "worker_process_pcap": process_ready,
        "device": capabilities.get("device_name"),
        "reason": None if process_ready else (capabilities.get("reason") or "worker_process_pcap_unavailable"),
    }
