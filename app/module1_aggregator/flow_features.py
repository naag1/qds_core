import math
from typing import Dict, List, Any

class Flow:
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = start_time
        self.last_time = start_time
        
        self.packet_count = 0
        self.total_bytes = 0
        # Online statistics keep memory O(number of flows), even for huge PCAPs.
        self.min_packet_length = 0
        self.max_packet_length = 0
        self._mean = 0.0
        self._m2 = 0.0
        
    def add_packet(self, pkt_len: int, timestamp: float):
        self.packet_count += 1
        self.total_bytes += pkt_len
        if self.packet_count == 1:
            self.min_packet_length = self.max_packet_length = pkt_len
        else:
            self.min_packet_length = min(self.min_packet_length, pkt_len)
            self.max_packet_length = max(self.max_packet_length, pkt_len)
        delta = pkt_len - self._mean
        self._mean += delta / self.packet_count
        self._m2 += delta * (pkt_len - self._mean)
        self.last_time = timestamp

    def to_features(self) -> Dict[str, Any]:
        """Extract statistical features from accumulated flow data."""
        duration = max(self.last_time - self.start_time, 0.000001)
        mean_len = self._mean if self.packet_count else 0
        variance = self._m2 / self.packet_count if self.packet_count else 0
        std_len = math.sqrt(variance)

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_duration": round(duration, 6),
            "total_packets": self.packet_count,
            "total_bytes": self.total_bytes,
            "packet_length_mean": round(mean_len, 2),
            "packet_length_std": round(std_len, 2),
            "bytes_per_second": round(self.total_bytes / duration, 2),
            "packets_per_second": round(self.packet_count / duration, 2),
        }
