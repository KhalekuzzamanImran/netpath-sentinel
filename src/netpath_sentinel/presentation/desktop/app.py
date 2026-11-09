import asyncio
import queue
import sys
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from netpath_sentinel.application.runner import DiagnosticRunner, WorkflowEvent
from netpath_sentinel.configuration.paths import app_data_dir
from netpath_sentinel.domain.enums import DiagnosticMode
from netpath_sentinel.domain.models import DiagnosticConfig
from netpath_sentinel.infrastructure.diagnostic_logging import log_exception
from netpath_sentinel.infrastructure.host import HostInspector
from netpath_sentinel.infrastructure.persistence import Repository
from netpath_sentinel.infrastructure.windows_capture import windows_capture_diagnostics


class DiagnosticWorker(QObject):
    completed = Signal(object)
    failed = Signal(str, object)
    finished = Signal()

    def __init__(
        self,
        runner: DiagnosticRunner,
        session_id: str,
        config: DiagnosticConfig,
        pcap_path: Path | None,
    ) -> None:
        super().__init__()
        self.runner = runner
        self.session_id = session_id
        self.config = config
        self.pcap_path = pcap_path
        self.pending_events: queue.Queue[WorkflowEvent] = queue.Queue(maxsize=512)
        self.loop: asyncio.AbstractEventLoop | None = None
        self.cancel_event: asyncio.Event | None = None

    @Slot()
    def run(self) -> None:
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.cancel_event = asyncio.Event()

            async def sink(event: WorkflowEvent) -> None:
                # A slow GUI applies backpressure here instead of accumulating Qt events.
                await asyncio.to_thread(self.pending_events.put, event)

            result = self.loop.run_until_complete(
                self.runner.run(
                    self.session_id, self.config, sink, self.pcap_path, self.cancel_event
                )
            )
            self.completed.emit(result)
        except Exception as exc:
            diagnostics = getattr(exc, "diagnostics", {})
            if not isinstance(diagnostics, dict):
                diagnostics = {}
            log_path = log_exception("diagnostic_workflow_failed", exc, diagnostics)
            self.failed.emit(
                str(exc),
                {"diagnostics": diagnostics, "log_path": str(log_path) if log_path else None},
            )
        except asyncio.CancelledError:
            # The runner has already emitted its terminal cancellation workflow event.
            pass
        finally:
            if self.loop:
                self.loop.close()
            self.finished.emit()

    def cancel(self) -> None:
        if self.loop and self.cancel_event:
            self.loop.call_soon_threadsafe(self.cancel_event.set)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetPath Sentinel")
        self.resize(1280, 820)
        self.inspector = HostInspector()
        self.repository = Repository(app_data_dir() / "netpath-sentinel.sqlite3")
        self.worker: DiagnosticWorker | None = None
        self.worker_thread: QThread | None = None
        self.pending_events: queue.Queue[WorkflowEvent] | None = None
        self.worker_status: QTextEdit | None = None
        self.event_timer = QTimer(self)
        self.event_timer.setInterval(20)
        self.event_timer.timeout.connect(self._drain_worker_events)
        self.session_id: str | None = None
        self.details = self._details_page()

        root = QWidget()
        layout = QHBoxLayout(root)
        sidebar = QListWidget()
        sidebar.setFixedWidth(220)
        sidebar.addItems(
            [
                "Overview",
                "New Diagnostic",
                "Session History",
                "Network Interfaces",
                "Routing Table",
                "Listening Ports",
                "Session Details",
                "Settings",
            ]
        )
        pages = QStackedWidget()
        pages.addWidget(self._overview())
        pages.addWidget(self._new_diagnostic())
        pages.addWidget(self._history())
        pages.addWidget(self._inspection_page("Network Interfaces", self._interfaces_text()))
        pages.addWidget(self._inspection_page("Routing Table", self._routes_text()))
        pages.addWidget(self._inspection_page("Listening Ports", self._listeners_text()))
        pages.addWidget(self.details)
        pages.addWidget(
            self._placeholder("Settings", "Capture, retention, privacy, and appearance settings.")
        )
        sidebar.currentRowChanged.connect(pages.setCurrentIndex)
        layout.addWidget(sidebar)
        layout.addWidget(pages, 1)
        self.setCentralWidget(root)
        self.pages = pages

    def _overview(self) -> QWidget:
        frame = QFrame()
        layout = QVBoxLayout(frame)
        title = QLabel("NetPath Sentinel")
        title.setStyleSheet("font-size: 28px; font-weight: 700")
        snapshot = self.inspector.snapshot()
        layout.addWidget(title)
        layout.addWidget(QLabel("Evidence-driven TCP diagnostics"))
        layout.addWidget(
            QLabel(
                f"Host: {snapshot.hostname}\nOS: {snapshot.os_version}\n"
                f"Interfaces: {len(snapshot.interfaces)}\nListeners: {len(snapshot.listeners)}"
            )
        )
        layout.addStretch()
        return frame

    def _new_diagnostic(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h2>New Diagnostic</h2>"))
        form = QFormLayout()
        name = QLineEdit("TCP connectivity check")
        mode = QComboBox()
        mode.addItems(["Passive Capture", "Active Diagnostic Listener", "PCAP Replay"])
        interface = QComboBox()
        interface.addItem("Automatic interface selection", None)
        for item in self.inspector.interfaces():
            interface.addItem(item.name, item.name)
        destination = QLineEdit()
        port = QSpinBox()
        port.setRange(1, 65535)
        port.setValue(6000)
        duration = QSpinBox()
        duration.setRange(1, 86400)
        duration.setValue(30)
        pcap = QLineEdit()
        browse = QPushButton("Browse")
        browse.clicked.connect(
            lambda: pcap.setText(
                QFileDialog.getOpenFileName(self, "Select PCAP", "", "PCAP (*.pcap *.pcapng)")[0]
            )
        )
        pcap_row = QWidget()
        pcap_layout = QHBoxLayout(pcap_row)
        pcap_layout.setContentsMargins(0, 0, 0, 0)
        pcap_layout.addWidget(pcap)
        pcap_layout.addWidget(browse)
        form.addRow("Session name", name)
        form.addRow("Diagnostic mode", mode)
        form.addRow("Interface", interface)
        form.addRow("Destination IP (optional)", destination)
        form.addRow("Destination TCP port", port)
        form.addRow("Observation duration (s)", duration)
        form.addRow("PCAP file (replay mode)", pcap_row)
        layout.addLayout(form)
        start = QPushButton("Create and start diagnostic")
        status = QTextEdit()
        status.setReadOnly(True)
        status.setMinimumHeight(180)
        layout.addWidget(start)
        layout.addWidget(status)
        layout.addStretch()

        def start_session() -> None:
            try:
                config = DiagnosticConfig(
                    name=name.text().strip(),
                    mode={
                        0: DiagnosticMode.PASSIVE_CAPTURE,
                        1: DiagnosticMode.ACTIVE_LISTENER,
                        2: DiagnosticMode.PCAP_REPLAY,
                    }[mode.currentIndex()],
                    interface=interface.currentData(),
                    destination_ip=ip_address(destination.text().strip())
                    if destination.text().strip()
                    else None,
                    destination_port=port.value(),
                    duration_seconds=duration.value(),
                )
                if config.mode != DiagnosticMode.PCAP_REPLAY and sys.platform == "win32":
                    capture_status = windows_capture_diagnostics()
                    if not capture_status["available"]:
                        message = (
                            "Windows live capture requires Npcap. "
                            f"{capture_status['reason']}\n\n"
                            "Install Npcap from https://npcap.com/, then restart "
                            "NetPath Sentinel. Npcap is not included with this installer."
                        )
                        log_path = log_exception(
                            "capture_preflight_failed",
                            RuntimeError(capture_status["reason"]),
                            capture_status,
                        )
                        if log_path:
                            message += f"\nDiagnostic log: {log_path}"
                        status.setPlainText(message)
                        QMessageBox.warning(self, "Capture setup required", message)
                        return
                session_id = str(uuid4())
                self.repository.save_session(session_id, config)
                replay = Path(pcap.text()) if pcap.text().strip() else None
                if config.mode == DiagnosticMode.PCAP_REPLAY and not replay:
                    raise ValueError("Select a PCAP file for replay mode")
                self.session_id = session_id
                self._start_worker(session_id, config, replay, status)
                self.pages.setCurrentIndex(6)
            except Exception as exc:
                status.setPlainText(f"Configuration error: {exc}")

        start.clicked.connect(start_session)
        return widget

    def _start_worker(
        self,
        session_id: str,
        config: DiagnosticConfig,
        replay: Path | None,
        status: QTextEdit | None = None,
    ) -> None:
        self.details.reset_view(session_id, config)
        self.worker_thread = QThread(self)
        self.worker = DiagnosticWorker(
            DiagnosticRunner(self.repository), session_id, config, replay
        )
        self.worker_status = status
        self.pending_events = self.worker.pending_events
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(self.worker.deleteLater)
        self.worker.completed.connect(self.details.finish)
        self.worker.failed.connect(self._handle_worker_error)
        self.event_timer.start()
        self.worker_thread.start()

    @Slot(str, object)
    def _handle_worker_error(self, error: str, context: object) -> None:
        details = context if isinstance(context, dict) else {}
        diagnostics = details.get("diagnostics", {})
        category = diagnostics.get("error_category") if isinstance(diagnostics, dict) else None
        log_path = details.get("log_path")
        actionable = error
        if category:
            actionable += f"\nCapture error category: {category}."
        actionable += (
            f"\nDiagnostic log: {log_path}"
            if log_path
            else "\nA diagnostic log could not be written; check the user data directory permissions."
        )
        self.details.fail(actionable, self.worker_status)

    @Slot()
    def _drain_worker_events(self) -> None:
        pending_events = self.pending_events
        if pending_events is not None:
            for _ in range(128):
                try:
                    event = pending_events.get_nowait()
                except queue.Empty:
                    break
                self.details.consume_event(event)
        if (
            self.worker_thread is None
            or not self.worker_thread.isRunning()
        ) and (pending_events is None or pending_events.empty()):
            self.event_timer.stop()

    def _history(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h2>Session History</h2>"))
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Name", "Status", "Created", "Session ID"])
        for item in self.repository.list_sessions():
            row = table.rowCount()
            table.insertRow(row)
            for col, value in enumerate([item.name, item.status, str(item.created_at), item.id]):
                table.setItem(row, col, QTableWidgetItem(value))

        def open_session(row: int, _column: int) -> None:
            session_item = table.item(row, 3)
            if not session_item:
                return
            session_id = session_item.text()
            stored = next(
                (item for item in self.repository.list_sessions() if item.id == session_id), None
            )
            if stored:
                config = DiagnosticConfig.model_validate(stored.config)
                self.session_id = session_id
                self.details.load_bundle(
                    session_id, config, self.repository.session_bundle(session_id)
                )
                self.pages.setCurrentIndex(6)

        table.cellDoubleClicked.connect(open_session)
        layout.addWidget(table)
        return widget

    def _details_page(self) -> "SessionDetails":
        return SessionDetails(self.repository)

    def _inspection_page(self, title: str, text: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel(f"<h2>{title}</h2>"))
        output = QTextEdit(text)
        output.setReadOnly(True)
        layout.addWidget(output)
        return widget

    def _interfaces_text(self) -> str:
        snapshot = self.inspector.snapshot()
        return (
            "\n".join(
                f"{i.name} | {'UP' if i.is_up else 'DOWN'} | {', '.join(i.addresses) or 'no addresses'}"
                for i in snapshot.interfaces
            )
            or "No interface data was available."
        )

    def _routes_text(self) -> str:
        snapshot = self.inspector.snapshot()
        routes = "\n".join(
            f"{r.destination} via {r.gateway or '-'} dev {r.interface or '-'} metric {r.metric if r.metric is not None else '-'}"
            for r in snapshot.routes
        )
        if snapshot.route_error:
            return f"{routes}\n{snapshot.route_error}" if routes else snapshot.route_error
        return routes or "No route data was available."

    def _listeners_text(self) -> str:
        return (
            "\n".join(
                f"{l.protocol.upper()} {l.local_address}:{l.local_port} {l.process or 'unknown'} (PID {l.pid or '-'})"
                for l in self.inspector.snapshot().listeners
            )
            or "No listening TCP sockets were observed."
        )

    @staticmethod
    def _placeholder(title: str, text: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        label = QLabel(f"<h2>{title}</h2><p>{text}</p>")
        label.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(label)
        layout.addStretch()
        return widget


class SessionDetails(QWidget):
    def __init__(self, repository: Repository) -> None:
        super().__init__()
        self.repository = repository
        self.session_id = ""
        layout = QVBoxLayout(self)
        self.title = QLabel("<h2>Session Details</h2>")
        layout.addWidget(self.title)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        controls = QHBoxLayout()
        self.stop = QPushButton("Cancel")
        self.export = QPushButton("Export JSON")
        self.stop.clicked.connect(self._cancel)
        self.export.clicked.connect(self._export)
        controls.addWidget(self.stop)
        controls.addWidget(self.export)
        controls.addStretch()
        layout.addLayout(controls)
        self.tabs = QTabWidget()
        self.overview = QTextEdit()
        self.overview.setReadOnly(True)
        self.workflow = QTextEdit()
        self.workflow.setReadOnly(True)
        self.connections = QTableWidget(0, 7)
        self.connections.setHorizontalHeaderLabels(
            ["Client", "Server", "State", "First seen", "Last seen", "Rx bytes", "Packets"]
        )
        self.timeline = QTableWidget(0, 8)
        self.timeline.setHorizontalHeaderLabels(
            ["Time", "Source", "Destination", "Flags", "Seq", "Ack", "Payload", "Session"]
        )
        self.payload = QTextEdit()
        self.payload.setReadOnly(True)
        self.heartbeat = QTextEdit()
        self.heartbeat.setReadOnly(True)
        self.evidence = QTextEdit()
        self.evidence.setReadOnly(True)
        self.findings = QTextEdit()
        self.findings.setReadOnly(True)
        self.report = QTextEdit()
        self.report.setReadOnly(True)
        for title, widget in [
            ("Overview", self.overview),
            ("Workflow", self.workflow),
            ("Live Connections", self.connections),
            ("TCP Timeline", self.timeline),
            ("Payload", self.payload),
            ("Heartbeat", self.heartbeat),
            ("Evidence", self.evidence),
            ("Root Cause Analysis", self.findings),
            ("Report", self.report),
        ]:
            self.tabs.addTab(widget, title)
        layout.addWidget(self.tabs)

    def reset_view(self, session_id: str, config: DiagnosticConfig) -> None:
        self.session_id = session_id
        self.progress.setValue(0)
        self.overview.setPlainText(f"Session {session_id}\nMode: {config.mode}\nStarting workflow...")
        self.workflow.clear()
        self.connections.setRowCount(0)
        self.timeline.setRowCount(0)
        self.payload.clear()
        self.evidence.clear()
        self.findings.clear()
        self.report.clear()

    def load_bundle(
        self, session_id: str, config: DiagnosticConfig, bundle: dict[str, list[dict[str, object]]]
    ) -> None:
        self.reset_view(session_id, config)
        self.progress.setValue(100)
        self.overview.setPlainText(
            f"Reopened session {session_id}\nMode: {config.mode}\nStored evidence loaded."
        )
        for packet in bundle["packets"]:
            row = self.timeline.rowCount()
            self.timeline.insertRow(row)
            for col, key in enumerate(
                [
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "flags",
                    "sequence",
                    "acknowledgement",
                    "payload_length",
                    "packet_number",
                ]
            ):
                self.timeline.setItem(row, col, QTableWidgetItem(str(packet.get(key, "-"))))
        self.findings.setPlainText(
            "\n\n".join(str(item) for item in bundle["findings"]) or "No stored findings."
        )

    @Slot(object)
    def consume_event(self, event: WorkflowEvent) -> None:
        self.progress.setValue(event.progress)
        self.workflow.append(f"[{event.status}] {event.stage_id}: {event.message}")
        if event.packet:
            row = self.timeline.rowCount()
            self.timeline.insertRow(row)
            values = [
                event.packet.timestamp.isoformat(),
                f"{event.packet.src_ip}:{event.packet.src_port}",
                f"{event.packet.dst_ip}:{event.packet.dst_port}",
                event.packet.flags,
                str(event.packet.sequence),
                str(event.packet.acknowledgement),
                str(event.packet.payload_length),
                event.tcp_session.id if event.tcp_session else "-",
            ]
            for col, value in enumerate(values):
                self.timeline.setItem(row, col, QTableWidgetItem(value))
            if event.tcp_session:
                self.connections.setRowCount(0)
                connection = event.tcp_session
                self.connections.insertRow(0)
                connection_values = [
                    f"{connection.client_ip}:{connection.client_port}",
                    f"{connection.server_ip}:{connection.server_port}",
                    connection.handshake,
                    connection.first_seen.isoformat(),
                    connection.last_seen.isoformat(),
                    str(connection.payload_bytes_client_to_server),
                    str(len(connection.packets)),
                ]
                for col, value in enumerate(connection_values):
                    self.connections.setItem(0, col, QTableWidgetItem(value))
            if event.packet.payload_preview_hex:
                self.payload.append(
                    f"{event.packet.timestamp.isoformat()} {event.packet.payload_preview_hex}"
                )
        if event.evidence:
            self.evidence.append(
                f"{event.evidence.evidence_type} [{event.evidence.status}]\n"
                f"{event.evidence.observation}\n"
            )
            if event.evidence.evidence_type == "heartbeat_status":
                self.heartbeat.setPlainText(str(event.evidence.observation))
        if event.finding:
            self.findings.append(
                f"[{event.finding.severity}] {event.finding.code}\n{event.finding.conclusion}\nNext: {event.finding.next_action}\n"
            )

    @Slot(object)
    def finish(self, result: object) -> None:
        self.progress.setValue(100)
        self.report.setPlainText(str(result))

    @Slot(str, object)
    def fail(self, error: str, status: QTextEdit | None = None) -> None:
        self.workflow.append(f"[failed] {error}")
        if status:
            status.setPlainText(error)

    def _cancel(self) -> None:
        window = self.window()
        if isinstance(window, MainWindow) and window.worker:
            window.worker.cancel()

    def _export(self) -> None:
        if not self.session_id:
            return
        bundle = self.repository.session_bundle(self.session_id)
        self.report.setPlainText(str(bundle))


def run() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
