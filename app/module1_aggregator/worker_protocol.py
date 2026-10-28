"""Versioned binary protocol helpers for the optional native Vulkan worker."""
import json
import struct
from typing import BinaryIO, Dict, Any

PROTOCOL_VERSION = 1
HEADER = struct.Struct("<I")

def write_message(stream: BinaryIO, payload: Dict[str, Any]) -> None:
    body = json.dumps({"version": PROTOCOL_VERSION, **payload}, separators=(",", ":")).encode()
    stream.write(HEADER.pack(len(body)))
    stream.write(body)
    stream.flush()

def read_message(stream: BinaryIO) -> Dict[str, Any] | None:
    raw = stream.read(HEADER.size)
    if not raw:
        return None
    if len(raw) != HEADER.size:
        raise ValueError("truncated worker message header")
    size = HEADER.unpack(raw)[0]
    if size > 64 * 1024 * 1024:
        raise ValueError("worker message exceeds 64 MiB")
    body = stream.read(size)
    if len(body) != size:
        raise ValueError("truncated worker message body")
    result = json.loads(body)
    if result.get("version") != PROTOCOL_VERSION:
        raise ValueError("unsupported worker protocol version")
    return result
