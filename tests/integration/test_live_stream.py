import asyncio
import threading

import pytest

from netpath_sentinel.application import runner as runner_module
from netpath_sentinel.application.runner import DiagnosticRunner
from netpath_sentinel.domain.enums import DiagnosticMode
from netpath_sentinel.domain.models import DiagnosticConfig, PacketEvent
from netpath_sentinel.infrastructure.capture import BoundedPacketQueue
from netpath_sentinel.infrastructure.persistence import Repository


def test_bounded_packet_queue_counts_overflow() -> None:
    packet = PacketEvent(
        src_ip="192.0.2.1",
        src_port=41000,
        dst_ip="192.0.2.2",
        dst_port=6000,
        flags="S",
    )
    packets = BoundedPacketQueue(capacity=1)
    packets.offer(packet)
    packets.offer(packet)
    assert packets.get(timeout=0) == packet
    assert packets.dropped == 1


@pytest.mark.asyncio
async def test_live_runner_streams_and_persists_before_capture_stops(
    tmp_path, monkeypatch
) -> None:
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(
        name="simulated live",
        mode=DiagnosticMode.PASSIVE_CAPTURE,
        interface="simulated0",
        destination_port=6000,
        duration_seconds=20,
    )
    repository.save_session("live-session", config)
    packet = PacketEvent(
        src_ip="192.0.2.1",
        src_port=41000,
        dst_ip="192.0.2.2",
        dst_port=6000,
        flags="S",
        sequence=100,
    )
    producer_stopped = threading.Event()

    def simulated_capture(_interface, _duration, _port, _max_packets, _filter,
                          stop_event, packet_queue, ready_event, _capture_payload):
        ready_event.set()
        packet_queue.offer(packet)
        if not stop_event.wait(timeout=2):
            raise AssertionError("capture did not stop after runner cancellation")
        producer_stopped.set()
        return []

    monkeypatch.setattr(runner_module, "capture_live", simulated_capture)
    cancel = asyncio.Event()
    events = []

    async def sink(event) -> None:
        events.append(event)
        if event.event_type == "packet":
            # The capture worker is still active when this live event reaches the sink.
            assert not producer_stopped.is_set()
            cancel.set()

    with pytest.raises(asyncio.CancelledError):
        await DiagnosticRunner(repository).run(
            "live-session", config, sink=sink, cancel_event=cancel
        )

    assert producer_stopped.is_set()
    assert [event.event_type for event in events if event.event_type in {"packet", "complete"}] == [
        "packet",
        "complete",
    ]
    assert events[-1].status == "cancelled"
    assert len(repository.session_bundle("live-session")["packets"]) == 1


@pytest.mark.asyncio
async def test_live_runner_cancels_idle_capture_without_leaking_worker(
    tmp_path, monkeypatch
) -> None:
    repository = Repository(tmp_path / "idle.sqlite3")
    config = DiagnosticConfig(
        name="simulated idle",
        mode=DiagnosticMode.PASSIVE_CAPTURE,
        interface="simulated0",
        duration_seconds=20,
    )
    repository.save_session("idle-session", config)
    stopped = threading.Event()

    def idle_capture(_interface, _duration, _port, _max_packets, _filter,
                     stop_event, _packet_queue, ready_event, _capture_payload):
        ready_event.set()
        if not stop_event.wait(timeout=2):
            raise AssertionError("idle capture was not interrupted")
        stopped.set()
        return []

    monkeypatch.setattr(runner_module, "capture_live", idle_capture)
    cancel = asyncio.Event()

    async def sink(event) -> None:
        if event.event_type == "stage" and event.stage_id == "packet_observation":
            cancel.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(
            DiagnosticRunner(repository).run(
                "idle-session", config, sink=sink, cancel_event=cancel
            ),
            timeout=1,
        )
    assert stopped.is_set()
