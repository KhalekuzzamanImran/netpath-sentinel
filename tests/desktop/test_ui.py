import os
import queue
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread
from PySide6.QtTest import QSignalSpy

from netpath_sentinel.application.runner import WorkflowEvent
from netpath_sentinel.domain.enums import StepStatus
from netpath_sentinel.domain.models import DiagnosticStep, PacketEvent
from netpath_sentinel.presentation.desktop.app import DiagnosticWorker, MainWindow


def test_main_window_exposes_diagnostic_and_details_pages(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "NetPath Sentinel"
    assert window.pages.count() == 8
    assert window.details.tabs.count() == 11
    window.sidebar.setCurrentRow(1)
    assert window.pages.currentIndex() == 1
    window.sidebar.setCurrentRow(6)
    assert window.pages.currentIndex() == 6


def test_diagnostic_worker_queues_events_and_finishes(qtbot) -> None:
    class StubRunner:
        async def run(self, session_id, _config, sink, _pcap_path, _cancel_event):
            await sink(
                WorkflowEvent(
                    session_id, "packet", "packet_observation", "running", 50, "simulated"
                )
            )
            return {"sessions": []}

    worker = DiagnosticWorker(StubRunner(), "worker-session", object(), None)
    thread = QThread()
    worker.moveToThread(thread)
    completion_spy = QSignalSpy(worker.completed)
    worker.finished.connect(thread.quit)
    worker.finished.connect(worker.deleteLater)
    thread.started.connect(worker.run)
    thread.start()
    qtbot.waitUntil(thread.isFinished, timeout=3000)
    event = worker.pending_events.get_nowait()
    assert event.message == "simulated"
    assert completion_spy.count() == 1
    thread.deleteLater()


def test_main_window_drains_bounded_event_queue(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    window.pending_events = queue.Queue(maxsize=2)
    window.pending_events.put(
        WorkflowEvent(
            "ui-session",
            "packet",
            "packet_observation",
            "running",
            45,
            "packet arrived",
            packet=PacketEvent(
                src_ip="192.0.2.1",
                src_port=41000,
                dst_ip="192.0.2.2",
                dst_port=6000,
                flags="S",
            ),
        )
    )
    window._drain_worker_events()
    assert window.details.timeline.rowCount() == 1


def test_main_window_displays_capture_category_and_diagnostic_log(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)

    window._handle_worker_error(
        "Npcap denied access to the selected adapter.",
        {
            "diagnostics": {"error_category": "permission_denied"},
            "log_path": str(tmp_path / "logs" / "netpath-sentinel.log"),
        },
    )

    message = window.details.workflow.toPlainText()
    assert "permission_denied" in message
    assert "netpath-sentinel.log" in message


def test_dashboard_theme_timeline_search_and_packet_inspector(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    packet = PacketEvent(
        src_ip="192.0.2.1",
        src_port=41000,
        dst_ip="192.0.2.2",
        dst_port=6000,
        flags="PA",
        sequence=10,
        acknowledgement=20,
        payload_length=4,
        payload_preview_hex=None,
    )
    window.details._append_packet_record(packet, "flow-1")
    window.details.timeline.selectRow(0)
    window.details._show_selected_packet()
    window.details.timeline_search.setText("192.0.2.1")

    assert window.details.timeline.rowCount() == 1
    assert not window.details.timeline.isRowHidden(0)
    assert "192.0.2.1:41000" in window.details.packet_inspector.toPlainText()
    assert "Payload preview" not in window.details.packet_inspector.toPlainText()
    window.update_dashboard(packet_count=1, session_count=1, status="Running")
    assert window._dashboard_values["packets"].text() == "1"
    assert "Capture is active" in window.dashboard_explanation.text()
    window._toggle_theme()
    assert window.dark_theme


def test_session_details_expand_structured_steps_and_findings(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    step = DiagnosticStep(
        session_id="s",
        step_id="capture",
        name="Prepare capture",
        status=StepStatus.WARNING,
        purpose="Open the chosen capture source",
        explanation="Capture stopped before readiness.",
        evidence_ids=["ev-1"],
        next_action="Select an available interface.",
    )

    window.details._update_step_tree(step)

    assert window.details.steps_tree.topLevelItemCount() == 1
    row = window.details.steps_tree.topLevelItem(0)
    assert row is not None and row.text(1) == "warning" and row.isExpanded()
    assert row.childCount() >= 3


def test_route_inspection_refreshes_current_snapshot(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    route = SimpleNamespace(
        destination="0.0.0.0/0",
        gateway="192.168.70.1",
        interface="Wi-Fi",
        interface_index=13,
        address_family="IPv4",
        metric=35,
    )
    window.inspector = SimpleNamespace(
        snapshot=lambda: SimpleNamespace(routes=[route], route_error=None)
    )

    window.sidebar.setCurrentRow(4)

    assert "0.0.0.0/0" in window._inspection_outputs[4].toPlainText()
    assert "192.168.70.1" in window._inspection_outputs[4].toPlainText()
    assert "index 13" in window._inspection_outputs[4].toPlainText()
