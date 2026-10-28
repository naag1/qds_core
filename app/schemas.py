from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

class FlowEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["v1"] = "v1"
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    flow_duration: float = Field(ge=0)
    total_packets: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    packet_length_mean: float = Field(default=0, ge=0)
    packet_length_std: float = Field(default=0, ge=0)
    # These are emitted by both the live sensor and offline parser.  The
    # service recomputes them from the authoritative counters and duration,
    # but they must be accepted at the API boundary.
    bytes_per_second: float = Field(default=0, ge=0)
    packets_per_second: float = Field(default=0, ge=0)
    observed_at: datetime | None = None

class SensorStatus(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    name: str = Field(min_length=1, max_length=128)
    platform: Literal["linux", "windows"]
    backend: Literal["cpu", "vulkan"] = "cpu"
    packet_drops: int = Field(default=0, ge=0)

class TriageUpdate(BaseModel):
    status: Literal["new", "investigating", "closed", "false_positive"]

class AlertView(BaseModel):
    id: int
    severity: str
    status: str
    created_at: datetime
    sensor_id: str
    detection: dict
    explanation_status: str
    explanation: str | None
