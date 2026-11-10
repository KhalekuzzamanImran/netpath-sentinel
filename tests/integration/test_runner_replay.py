import asyncio
import ipaddress
import struct
from pathlib import Path

import pytest

from netpath_sentinel.application.runner import DiagnosticRunner
from netpath_sentinel.domain.models import DiagnosticConfig
from netpath_sentinel.infrastructure.persistence import Repository


def frame(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: int,
    seq: int,
    ack: int = 0,
    payload: bytes = b"",
) -> bytes:
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    source = ipaddress.ip_address(src).packed
    destination = ipaddress.ip_address(dst).packed
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, source, destination)
    return ethernet + ip + tcp


def write_pcap(path, frames: list[bytes]) -> None:
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, item in enumerate(frames, start=1):
            stream.write(struct.pack("<IIII", index, 0, len(item), len(item)))
            stream.write(item)


@pytest.mark.asyncio
async def test_replay_runner_streams_packets_persists_findings_and_reports(tmp_path) -> None:
    pcap = tmp_path / "handshake.pcap"
    packets = [
        frame("10.1.1.2", "10.1.1.1", 41000, 6000, 0x02, 10),
        frame("10.1.1.1", "10.1.1.2", 6000, 41000, 0x12, 20, 11),
        frame("10.1.1.2", "10.1.1.1", 41000, 6000, 0x10, 11, 21),
        frame("10.1.1.2", "10.1.1.1", 41000, 6000, 0x18, 11, 21, b"HB\n"),
    ]
    write_pcap(pcap, packets)
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(name="replay", mode="pcap_replay", destination_port=6000)
    repository.save_session("session-1", config)
    events: list[str] = []

    async def sink(event) -> None:
        events.append(event.event_type)

    result = await DiagnosticRunner(repository).run("session-1", config, sink, pcap)
    assert "packet" in events
    assert result["sessions"][0].handshake == "complete"
    assert result["sessions"][0].payload_bytes_client_to_server == 3
    assert (tmp_path / "reports" / "session-1.html").exists()
    assert (tmp_path / "reports" / "session-1-executive.html").exists()
    assert result["json_report"].is_file()
    assert len(repository.session_bundle("session-1")["packets"]) == 4
    reports = repository.session_bundle("session-1")["reports"]
    assert len(reports) == 2
    assert {Path(item["html_path"]).name for item in reports} == {
        "session-1.html",
        "session-1-executive.html",
    }
    assert result["report"]["metrics"]["tcp_sessions"] == 1


@pytest.mark.asyncio
async def test_replay_runner_cancellation_marks_session(tmp_path) -> None:
    pcap = tmp_path / "empty.pcap"
    write_pcap(pcap, [])
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(name="cancel", mode="pcap_replay", destination_port=6000)
    repository.save_session("session-2", config)
    cancel = asyncio.Event()
    cancel.set()
    with pytest.raises(asyncio.CancelledError):
        await DiagnosticRunner(repository).run(
            "session-2", config, pcap_path=pcap, cancel_event=cancel
        )
    assert repository.list_sessions()[0].status == "cancelled"


@pytest.mark.asyncio
async def test_replay_respects_packet_limit_and_marks_evidence_incomplete(tmp_path) -> None:
    pcap = tmp_path / "limited.pcap"
    packet = frame("10.1.1.2", "10.1.1.1", 41000, 6000, 0x10, 10, 0)
    write_pcap(pcap, [packet, packet, packet])
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(
        name="limited replay", mode="pcap_replay", destination_port=6000, max_packets=2
    )
    repository.save_session("limited-session", config)
    summaries = []

    async def sink(event) -> None:
        if event.evidence and event.evidence.evidence_type == "packet_summary":
            summaries.append(event.evidence)

    await DiagnosticRunner(repository).run("limited-session", config, sink, pcap)
    assert len(repository.session_bundle("limited-session")["packets"]) == 2
    assert len(summaries) == 1
    assert summaries[0].status.value == "incomplete"
    assert summaries[0].observation["packet_limit_reached"] is True
    assert summaries[0].observation["capture_complete"] is False


@pytest.mark.asyncio
async def test_malformed_pcap_fails_workflow_with_terminal_error(tmp_path) -> None:
    pcap = tmp_path / "malformed.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02")
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(name="malformed replay", mode="pcap_replay", destination_port=6000)
    repository.save_session("malformed-session", config)
    events = []

    async def sink(event) -> None:
        events.append(event)

    with pytest.raises(ValueError, match="invalid PCAP global header"):
        await DiagnosticRunner(repository).run("malformed-session", config, sink, pcap)
    assert repository.list_sessions()[0].status == "failed"
    assert events[-1].event_type == "error"
    assert events[-1].status == "failed"
