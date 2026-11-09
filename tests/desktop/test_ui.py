import os
import queue

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThread
from PySide6.QtTest import QSignalSpy

from netpath_sentinel.application.runner import WorkflowEvent
from netpath_sentinel.domain.models import PacketEvent
from netpath_sentinel.presentation.desktop.app import DiagnosticWorker, MainWindow


def test_main_window_exposes_diagnostic_and_details_pages(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "NetPath Sentinel"
    assert window.pages.count() == 8
    assert window.details.tabs.count() == 9


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
