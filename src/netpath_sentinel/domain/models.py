from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from .enums import Confidence, DiagnosticMode, EvidenceStatus, Severity, StepStatus


def utc_now() -> datetime:
    return datetime.now(UTC)


class InterfaceInfo(BaseModel):
    name: str
    is_up: bool
    mtu: int | None = None
    mac: str | None = None
    addresses: list[str] = Field(default_factory=list)
    rx_bytes: int | None = None
    tx_bytes: int | None = None


class RouteInfo(BaseModel):
    destination: str
    gateway: str | None = None
    interface: str | None = None
    source: str | None = None
    interface_index: int | None = None
    address_family: str | None = None
    route_metric: int | None = None
    interface_metric: int | None = None
    metric: int | None = None


class ListenerInfo(BaseModel):
    protocol: str
    local_address: str
    local_port: int
    pid: int | None = None
    process: str | None = None
    state: str


class DiagnosticConfig(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    name: str = Field(min_length=1, max_length=120)
    mode: DiagnosticMode = DiagnosticMode.PASSIVE_CAPTURE
    interface: str | None = None
    destination_ip: IPvAnyAddress | None = None
    destination_port: int = Field(default=6000, ge=1, le=65535)
    source_ip: IPvAnyAddress | None = None
    duration_seconds: int = Field(default=30, ge=1, le=86400)
    capture_payload: bool = False
    max_packets: int = Field(default=100_000, ge=1, le=5_000_000)
    max_capture_bytes: int = Field(default=250_000_000, ge=1_000_000)
    heartbeat_mode: str = "disabled"
    expected_heartbeat_interval: float | None = Field(default=None, gt=0)
    heartbeat_timeout: float | None = Field(default=None, gt=0)

    @field_validator("heartbeat_timeout")
    @classmethod
    def timeout_after_interval(cls, value: float | None, info: Any) -> float | None:
        interval = info.data.get("expected_heartbeat_interval")
        if value is not None and interval is not None and value < interval:
            raise ValueError("heartbeat timeout must be at least the expected interval")
        return value


class PacketEvent(BaseModel):
    timestamp: datetime = Field(default_factory=utc_now)
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    flags: str
    sequence: int | None = None
    acknowledgement: int | None = None
    payload_length: int = 0
    payload_preview_hex: str | None = None
    packet_number: int | None = None
    capture_interface: str | None = None
    truncated: bool = False
    payload_data: bytes = Field(default=b"", exclude=True, repr=False)


class TCPSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    packets: list[PacketEvent] = Field(default_factory=list)
    handshake: str = "not_observed"
    payload_bytes_client_to_server: int = 0
    payload_bytes_server_to_client: int = 0
    retransmissions: int = 0
    capture_started_midstream: bool = False
    observed_state: str = "unknown"
    stream_client_to_server: str = ""
    stream_server_to_client: str = ""
    stream_incomplete: bool = False
    duplicate_acks: int = 0
    out_of_order_segments: int = 0
    fin_client_observed: bool = False
    fin_server_observed: bool = False


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    evidence_type: str
    source: str
    collected_at: datetime = Field(default_factory=utc_now)
    status: EvidenceStatus
    observation: dict[str, Any] = Field(default_factory=dict)
    raw_reference: str | None = None
    tcp_session_id: str | None = None
    reliability: str = "normal"


class DiagnosticStep(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    step_id: str
    name: str
    status: StepStatus = StepStatus.PENDING
    purpose: str = ""
    started_at: datetime | None = None
    ended_at: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    explanation: str = ""
    confidence: Confidence = Confidence.INCONCLUSIVE
    recommended_verification: str = ""
    next_action: str = ""
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    code: str
    severity: Severity
    conclusion: str
    confidence: Confidence
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_verification: str
    next_action: str
