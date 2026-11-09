from datetime import UTC, datetime

from netpath_sentinel.analysis.heartbeat import evaluate_heartbeat
from netpath_sentinel.analysis.tcp import TCPSessionTracker
from netpath_sentinel.domain.models import DiagnosticConfig, PacketEvent


def packet(
    flags: str, src_port: int = 40000, dst_port: int = 6000, payload: int = 0
) -> PacketEvent:
    server_packet = src_port == 6000
    return PacketEvent(
        timestamp=datetime.now(UTC),
        src_ip="10.0.0.1" if server_packet else "10.0.0.2",
        src_port=src_port,
        dst_ip="10.0.0.2" if server_packet else "10.0.0.1",
        dst_port=dst_port,
        flags=flags,
        sequence=1,
        acknowledgement=1,
        payload_length=payload,
    )


def test_config_allows_missing_source_ip() -> None:
    config = DiagnosticConfig(name="gateway check", destination_port=6000)
    assert config.source_ip is None


def test_tracker_detects_complete_handshake_and_payload() -> None:
    tracker = TCPSessionTracker(server_port=6000)
    items = [
        packet("S"),
        packet("SA", src_port=6000, dst_port=40000),
        packet("A"),
        packet("PA", payload=5),
    ]
    for item in items:
        tracker.ingest(item)
    assert len(tracker.sessions) == 1
    assert tracker.sessions[0].handshake == "complete"
    assert tracker.sessions[0].payload_bytes_client_to_server == 5


def test_tracker_marks_midstream_capture() -> None:
    tracker = TCPSessionTracker(server_port=6000)
    tracker.ingest(packet("A"))
    assert tracker.sessions[0].capture_started_midstream
    assert tracker.sessions[0].handshake == "not_observed_midstream"


def test_heartbeat_disabled_and_overdue() -> None:
    now = datetime.now(UTC)
    assert evaluate_heartbeat(None, None, now, 5, 10, "disabled")["status"] == "not_configured"
    assert evaluate_heartbeat(
        now, now.replace(second=max(now.second - 20, 0)), now, 5, 10, "ascii"
    )["status"] in {"healthy", "overdue"}
