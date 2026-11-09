import asyncio
import json
import os
import socket
import threading
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QComboBox, QLineEdit, QPushButton, QSpinBox

from netpath_sentinel.application.runner import DiagnosticRunner
from netpath_sentinel.domain.enums import DiagnosticMode
from netpath_sentinel.domain.models import DiagnosticConfig
from netpath_sentinel.infrastructure.persistence import Repository, StoredEvidence, StoredReport
from netpath_sentinel.infrastructure.windows_capture import windows_capture_diagnostics
from netpath_sentinel.presentation.desktop.app import MainWindow


@pytest.mark.windows_live
@pytest.mark.asyncio
async def test_npcap_loopback_diagnostic_acceptance(tmp_path) -> None:
    diagnostics = windows_capture_diagnostics()
    if not diagnostics["supported"]:
        pytest.skip("Native Npcap capture acceptance only runs on Windows.")
    if not diagnostics["available"]:
        pytest.skip(f"Npcap runtime unavailable: {diagnostics['reason']}")

    requested_port = int(os.environ.get("NETPATH_SENTINEL_TEST_PORT", "0"))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", requested_port))
        port = probe.getsockname()[1]

    received: list[bytes] = []
    server_ready = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.read(256))
        writer.close()
        await writer.wait_closed()

    async def sink(event) -> None:
        if event.event_type == "stage" and event.stage_id == "capture_preparation":
            if event.status == "passed":
                capture_ready.set()
        events.append(event)

    capture_ready = asyncio.Event()
    events = []
    repository = Repository(tmp_path / "npcap-live.sqlite3")
    config = DiagnosticConfig(
        name="Npcap loopback acceptance",
        mode=DiagnosticMode.PASSIVE_CAPTURE,
        interface="Loopback Pseudo-Interface 1",
        destination_ip="127.0.0.1",
        destination_port=port,
        duration_seconds=4,
        capture_payload=True,
    )
    repository.save_session("npcap-live-session", config)
    runner_task = asyncio.create_task(
        DiagnosticRunner(repository).run("npcap-live-session", config, sink=sink)
    )
    server = None
    try:
        await asyncio.wait_for(capture_ready.wait(), timeout=10)
        server = await asyncio.start_server(handle, "127.0.0.1", port)
        server_ready.set()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"phase5-test-payload")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        await reader.read()
        result = await asyncio.wait_for(runner_task, timeout=12)
    finally:
        if server:
            server.close()
            await server.wait_closed()
        if not runner_task.done():
            runner_task.cancel()
            await asyncio.gather(runner_task, return_exceptions=True)

    assert server_ready.is_set()
    assert received == [b"phase5-test-payload"]
    packet_events = [event for event in events if event.event_type == "packet"]
    assert packet_events, "Npcap reported ready but captured no loopback TCP events"
    completion_index = next(
        index for index, event in enumerate(events) if event.event_type == "complete"
    )
    assert events.index(packet_events[0]) < completion_index
    assert all(event.packet is not None and event.packet.timestamp for event in packet_events)
    observed_flags = {event.packet.flags for event in packet_events if event.packet}
    assert {"S", "SA", "A"}.issubset(observed_flags)
    assert any(session.handshake == "complete" for session in result["sessions"])
    assert any(session.payload_bytes_client_to_server >= len(b"phase5-test-payload")
               for session in result["sessions"])
    assert repository.session_bundle("npcap-live-session")["packets"]
    assert result["findings"]
    assert result["html_report"].exists()
    assert result["json_report"].exists()


@pytest.mark.windows_live
@pytest.mark.asyncio
async def test_npcap_loopback_idle_capture_cancels_and_persists_partial_evidence(tmp_path) -> None:
    diagnostics = windows_capture_diagnostics()
    if not diagnostics["supported"] or not diagnostics["available"]:
        pytest.skip(f"Usable Npcap runtime unavailable: {diagnostics['reason']}")

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    repository = Repository(tmp_path / "npcap-cancel.sqlite3")
    config = DiagnosticConfig(
        name="Npcap idle cancellation",
        mode=DiagnosticMode.PASSIVE_CAPTURE,
        interface="Loopback Pseudo-Interface 1",
        destination_ip="127.0.0.1",
        destination_port=port,
        duration_seconds=30,
    )
    repository.save_session("npcap-cancel-session", config)
    cancel = asyncio.Event()
    capture_ready = asyncio.Event()
    events = []

    async def sink(event) -> None:
        events.append(event)
        if event.event_type == "stage" and event.stage_id == "capture_preparation":
            if event.status == "passed":
                capture_ready.set()

    task = asyncio.create_task(
        DiagnosticRunner(repository).run(
            "npcap-cancel-session", config, sink=sink, cancel_event=cancel
        )
    )
    try:
        await asyncio.wait_for(capture_ready.wait(), timeout=10)
        started = time.monotonic()
        cancel.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=3)
        latency = time.monotonic() - started
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert latency < 2.0
    assert repository.list_sessions()[0].status == "cancelled"
    with repository.sessions() as db:
        partial = (
            db.query(StoredEvidence)
            .filter_by(session_id="npcap-cancel-session", evidence_type="packet_summary")
            .one()
        )
    assert partial.status == "incomplete"
    assert partial.observation["capture_complete"] is False
    assert events[-1].event_type == "complete"
    assert events[-1].status == "cancelled"
    (tmp_path / "cancellation-evidence.json").write_text(
        json.dumps(
            {
                "cancel_latency_seconds": latency,
                "capture_status": partial.status,
                "terminal_event": events[-1].status,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


@pytest.mark.windows_live
def test_npcap_loopback_events_update_qt_ui_while_capture_is_running(
    qtbot, monkeypatch, tmp_path
) -> None:
    diagnostics = windows_capture_diagnostics()
    if not diagnostics["supported"] or not diagnostics["available"]:
        pytest.skip(f"Usable Npcap runtime unavailable: {diagnostics['reason']}")
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    window = MainWindow()
    qtbot.addWidget(window)
    combos = window.findChildren(QComboBox)
    line_edits = window.findChildren(QLineEdit)
    spinboxes = window.findChildren(QSpinBox)
    combos[1].setCurrentIndex(combos[1].findData("Loopback Pseudo-Interface 1"))
    line_edits[0].setText("Npcap Qt live acceptance")
    spinboxes[0].setValue(port)
    spinboxes[1].setValue(8)
    window.pages.setCurrentIndex(1)
    start = next(button for button in window.findChildren(QPushButton)
                 if button.text() == "Create and start diagnostic")
    start.click()
    qtbot.waitUntil(
        lambda: "Capture ready: live:Loopback Pseudo-Interface 1"
        in window.details.workflow.toPlainText(),
        timeout=10000,
    )

    server = socket.socket()
    server.settimeout(4)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    received: list[bytes] = []

    def receive_payload() -> None:
        try:
            connection, _address = server.accept()
            with connection:
                received.append(connection.recv(256))
        finally:
            server.close()

    listener_thread = threading.Thread(target=receive_payload, daemon=True)
    listener_thread.start()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(b"phase8-qt-payload")
    qtbot.waitUntil(lambda: window.details.timeline.rowCount() >= 1, timeout=5000)
    assert window.worker_thread is not None and window.worker_thread.isRunning()
    assert "Capture ready" in window.details.workflow.toPlainText()
    listener_thread.join(timeout=3)
    assert received == [b"phase8-qt-payload"]

    qtbot.waitUntil(lambda: bool(window.details.report.toPlainText()), timeout=12000)
    assert window.session_id is not None
    assert window.repository.session_bundle(window.session_id)["packets"]
    with window.repository.sessions() as db:
        report = db.query(StoredReport).filter_by(session_id=window.session_id).one()
    assert Path(report.html_path).is_file()
    assert Path(report.json_path).is_file()
    assert "TCP_HANDSHAKE_COMPLETE" in window.details.findings.toPlainText()
    qtbot.waitUntil(lambda: not window.worker_thread.isRunning(), timeout=3000)
