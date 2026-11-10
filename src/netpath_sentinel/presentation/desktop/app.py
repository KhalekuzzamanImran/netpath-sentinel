import asyncio
import queue
import sys
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import uuid4

from PySide6.QtCore import QObject, QSettings, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QCloseEvent, QColor, QDesktopServices, QPainter, QPalette, QPen
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
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
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from netpath_sentinel import __version__
from netpath_sentinel.application.runner import DiagnosticRunner, WorkflowEvent
from netpath_sentinel.configuration.paths import app_data_dir
from netpath_sentinel.domain.enums import DiagnosticMode
from netpath_sentinel.domain.models import (
    DiagnosticConfig,
    DiagnosticStep,
    Finding,
    PacketEvent,
    TCPSession,
)
from netpath_sentinel.infrastructure.diagnostic_logging import log_exception
from netpath_sentinel.infrastructure.host import HostInspector
from netpath_sentinel.infrastructure.persistence import Repository
from netpath_sentinel.infrastructure.windows_capture import windows_capture_diagnostics


class TCPFlowDiagram(QWidget):
    """Compact, accessible sequence view for packets in the selected TCP flow."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumSize(560, 300)
        self.setAccessibleName("TCP client and server sequence diagram")
        self._session: TCPSession | None = None

    def set_session(self, session: TCPSession | None) -> None:
        self._session = session
        self.update()

    def paintEvent(self, _event: object) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), self.palette().color(QPalette.ColorRole.Base))
        painter.setPen(self.palette().color(QPalette.ColorRole.Text))
        painter.drawText(24, 28, "Client")
        painter.drawText(max(24, self.width() - 150), 28, "Server")
        left, right = 82, self.width() - 82
        top, bottom = 45, self.height() - 24
        painter.setPen(QPen(QColor("#aab6c7"), 2))
        painter.drawLine(left, top, left, bottom)
        painter.drawLine(right, top, right, bottom)
        session = self._session
        if session is None:
            painter.setPen(QColor("#718096"))
            painter.drawText(24, self.height() // 2, "Start or open a session to view packet direction and sequence.")
            return
        packets = list(getattr(session, "packets", []))[-20:]
        if not packets:
            painter.drawText(24, self.height() // 2, "No retained packet events for this flow.")
            return
        available = max(70, bottom - top - 18)
        for index, packet in enumerate(packets):
            y = top + 12 + int((index / max(1, len(packets) - 1)) * available)
            is_client = (
                packet.src_ip == getattr(session, "client_ip", None)
                and packet.src_port == getattr(session, "client_port", None)
            )
            start, end = (left + 5, right - 5) if is_client else (right - 5, left + 5)
            flags = packet.flags
            color = QColor("#16835d" if "S" in flags else "#bd5b23" if "R" in flags else "#2867c7")
            painter.setPen(QPen(color, 2))
            painter.drawLine(start, y, end, y)
            painter.drawLine(end, y, end - (8 if is_client else -8), y - 5)
            painter.drawLine(end, y, end - (8 if is_client else -8), y + 5)
            painter.setPen(color)
            label = f"{flags or 'ACK'} | seq {packet.sequence} | ack {packet.acknowledgement} | {packet.payload_length} B"
            painter.drawText(min(left, right) + 8, y - 5, label)


class SessionHistoryLoader(QObject):
    loaded = Signal(object)
    failed = Signal(str)

    def __init__(self, repository: Repository) -> None:
        super().__init__()
        self.repository = repository

    @Slot()
    def run(self) -> None:
        try:
            self.loaded.emit(
                [
                    {
                        "id": item.id,
                        "name": item.name,
                        "status": item.status,
                        "created_at": str(item.created_at),
                    }
                    for item in self.repository.list_sessions()
                ]
            )
        except Exception as exc:
            self.failed.emit(str(exc))


class SessionBundleLoader(QObject):
    loaded = Signal(str, object, object)
    failed = Signal(str)

    def __init__(self, repository: Repository, session_id: str) -> None:
        super().__init__()
        self.repository = repository
        self.session_id = session_id

    @Slot()
    def run(self) -> None:
        try:
            session = next(
                (item for item in self.repository.list_sessions() if item.id == self.session_id),
                None,
            )
            if session is None:
                raise LookupError("The selected diagnostic session is no longer available.")
            self.loaded.emit(
                self.session_id,
                DiagnosticConfig.model_validate(session.config),
                self.repository.session_bundle(self.session_id),
            )
        except Exception as exc:
            self.failed.emit(str(exc))


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
            repository = getattr(self.runner, "repository", None)
            if repository is not None:
                repository.save_session(self.session_id, self.config)

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
        self.setMinimumSize(880, 600)
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
        self._closing = False
        self._threads: list[QThread] = []
        self._history_load_started = False
        self._history_rows: list[dict[str, str]] = []
        self._inspection_outputs: dict[int, QTextEdit] = {}
        self._dashboard_values: dict[str, QLabel] = {}
        self._report_paths: dict[str, Path] = {}
        self._settings = QSettings("NetPathSentinel", "Desktop")
        self.dark_theme = self._settings.value("dark_theme", False, type=bool)
        self.details = self._details_page()

        root = QWidget()
        layout = QHBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)
        sidebar_panel = QFrame()
        sidebar_panel.setObjectName("sidebarPanel")
        sidebar_layout = QVBoxLayout(sidebar_panel)
        brand = QLabel("NETPATH\nSENTINEL")
        brand.setObjectName("brandLabel")
        brand.setAccessibleName("NetPath Sentinel navigation")
        sidebar_layout.addWidget(brand)
        sidebar = QListWidget()
        self.sidebar = sidebar
        sidebar.setMinimumWidth(180)
        sidebar.setMaximumWidth(250)
        sidebar.setAccessibleName("Main navigation")
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
        sidebar_layout.addWidget(sidebar, 1)
        self.theme_button = QPushButton()
        self.theme_button.clicked.connect(self._toggle_theme)
        sidebar_layout.addWidget(self.theme_button)
        pages = QStackedWidget()
        self.pages = pages
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
        sidebar.currentRowChanged.connect(self._navigate)
        layout.addWidget(sidebar_panel)
        layout.addWidget(pages, 1)
        self.setCentralWidget(root)
        self._apply_theme()
        sidebar.setCurrentRow(0)

    def _navigate(self, row: int) -> None:
        self.pages.setCurrentIndex(row)
        if row == 2 and not self._history_load_started:
            self._history_load_started = True
            self._start_history_load()
        output = self._inspection_outputs.get(row)
        if output is not None:
            getter = {
                3: self._interfaces_text,
                4: self._routes_text,
                5: self._listeners_text,
            }.get(row)
            if getter:
                output.setPlainText(getter())

    def update_dashboard(self, **values: object) -> None:
        labels = {
            "status": "status",
            "sessions": "sessions",
            "tcp_sessions": "sessions",
            "session_count": "sessions",
            "packets": "packets",
            "packets_observed": "packets",
            "packet_count": "packets",
            "retransmissions": "retransmissions",
            "findings": "findings",
        }
        for key, value in values.items():
            target = labels.get(key)
            if target and target in self._dashboard_values:
                self._dashboard_values[target].setText(str(value))
                self._dashboard_values[target].setAccessibleName(
                    f"{target.replace('_', ' ').title()}: {value}"
                )
        if "status" in values and hasattr(self, "dashboard_explanation"):
            explanation = {
                "Running": "Capture is active. Packet events and session state are updating as traffic arrives.",
                "Completed": "The workflow completed. Review findings with their evidence and capture limitations.",
                "Cancelled": "Capture stopped. Partial observations remain available for review.",
            }.get(str(values["status"]), "The diagnostic workflow is ready.")
            self.dashboard_explanation.setText(explanation)

    def _toggle_theme(self) -> None:
        self.dark_theme = not self.dark_theme
        self._settings.setValue("dark_theme", self.dark_theme)
        self._apply_theme()

    def _apply_theme(self) -> None:
        if self.dark_theme:
            colors = {
                "window": "#151a22",
                "panel": "#1d2531",
                "text": "#e9eef7",
                "muted": "#aeb9c9",
                "line": "#394455",
                "accent": "#78aaff",
                "select": "#263b58",
            }
            self.theme_button.setText("Switch to light theme")
        else:
            colors = {
                "window": "#f3f6fa",
                "panel": "#ffffff",
                "text": "#18263a",
                "muted": "#53647a",
                "line": "#d9e1ec",
                "accent": "#175fc5",
                "select": "#e7effb",
            }
            self.theme_button.setText("Switch to dark theme")
        self.setStyleSheet(
            "QMainWindow,QWidget{{background:{window};color:{text};font-family:'Segoe UI',Arial,sans-serif;font-size:14px}}"
            "QFrame#sidebarPanel,QFrame#metricCard,QGroupBox{{background:{panel};border:1px solid {line};border-radius:12px}}"
            "QLabel#brandLabel{{font-size:18px;font-weight:800;letter-spacing:2px;padding:14px;color:{accent}}}"
            "QListWidget{{background:transparent;border:0;padding:4px;outline:0}}"
            "QListWidget::item{{padding:12px;border-radius:8px;margin:2px}}"
            "QListWidget::item:selected{{background:{select};color:{accent};font-weight:700}}"
            "QPushButton{{background:{panel};border:1px solid {line};border-radius:8px;padding:9px 13px}}"
            "QPushButton:hover{{border-color:{accent}}} QPushButton:focus{{outline:2px solid {accent}}}"
            "QLineEdit,QComboBox,QSpinBox,QTextEdit,QTableWidget,QTreeWidget,QTabWidget::pane{{background:{panel};border:1px solid {line};border-radius:6px;padding:5px}}"
            "QHeaderView::section{{background:{select};color:{text};border:0;padding:7px}}"
            "QTabBar::tab{{background:{window};padding:9px 12px;border:1px solid {line};border-radius:6px}}"
            "QTabBar::tab:selected{{background:{select};color:{accent}}}"
            "QProgressBar{{border:1px solid {line};border-radius:7px;text-align:center;height:18px}}"
            "QProgressBar::chunk{{background:{accent};border-radius:6px}}".format(**colors)
        )

    def _overview(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        frame = QWidget()
        layout = QVBoxLayout(frame)
        layout.setSpacing(18)
        heading = QLabel("Network health dashboard")
        heading.setStyleSheet("font-size:26px;font-weight:750")
        snapshot = self.inspector.snapshot()
        host_label = QLabel(
            f"{snapshot.hostname}  |  {snapshot.os_name}  |  {len(snapshot.interfaces)} adapters available  |  Version {__version__}"
        )
        host_label.setAccessibleName("Host and adapter summary")
        layout.addWidget(heading)
        layout.addWidget(host_label)
        cards = QHBoxLayout()
        for key, label, initial in (
            ("status", "Diagnostic status", "Ready"),
            ("sessions", "TCP sessions", "0"),
            ("packets", "Packets", "0"),
            ("retransmissions", "Retransmissions", "0"),
            ("findings", "Findings", "0"),
        ):
            card = QFrame()
            card.setObjectName("metricCard")
            card_layout = QVBoxLayout(card)
            caption = QLabel(label)
            caption.setStyleSheet("color:#627289;font-size:12px")
            value = QLabel(initial)
            value.setStyleSheet("font-size:22px;font-weight:700")
            value.setAccessibleName(f"{label}: {initial}")
            card_layout.addWidget(caption)
            card_layout.addWidget(value)
            cards.addWidget(card)
            self._dashboard_values[key] = value
        layout.addLayout(cards)
        summary = QFrame()
        summary.setObjectName("metricCard")
        summary_layout = QVBoxLayout(summary)
        summary_layout.addWidget(QLabel("What this means"))
        self.dashboard_explanation = QLabel(
            "No diagnostic is active. Start a guided capture to observe a TCP connection and review evidence-backed findings."
        )
        self.dashboard_explanation.setWordWrap(True)
        summary_layout.addWidget(self.dashboard_explanation)
        start = QPushButton("Start a guided diagnostic")
        start.setAccessibleName("Start a guided diagnostic")
        start.clicked.connect(lambda: self.sidebar.setCurrentRow(1))
        summary_layout.addWidget(start)
        layout.addWidget(summary)
        layout.addStretch()
        scroll.setWidget(frame)
        return scroll

    def _new_diagnostic(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("<h2>Guided TCP diagnostic</h2>"))
        layout.addWidget(
            QLabel("Choose the target and capture source. NetPath Sentinel reports only what this host observes.")
        )
        wizard = QTabWidget()
        wizard.setAccessibleName("Diagnostic setup steps")
        self.config_wizard = wizard
        scope = QWidget()
        scope_layout = QVBoxLayout(scope)
        form = QFormLayout()
        name = QLineEdit("TCP connectivity check")
        name.setObjectName("diagnosticName")
        mode = QComboBox()
        mode.addItems(["Passive Capture", "Active Diagnostic Listener", "PCAP Replay"])
        mode.setObjectName("diagnosticMode")
        form.addRow("Session name", name)
        form.addRow("Diagnostic mode", mode)
        scope_layout.addLayout(form)
        scope_layout.addWidget(
            QLabel("Passive capture observes traffic without opening a listener. Replay analyzes an existing capture file.")
        )
        scope_layout.addStretch()
        wizard.addTab(scope, "1 - Scope")

        capture_page = QWidget()
        capture_layout = QVBoxLayout(capture_page)
        capture_form = QFormLayout()
        interface = QComboBox()
        interface.addItem("Automatic interface selection", None)
        for item in self.inspector.interfaces():
            interface.addItem(item.name, item.name)
        interface.setObjectName("captureInterface")
        destination = QLineEdit()
        destination.setObjectName("destinationAddress")
        port = QSpinBox()
        port.setRange(1, 65535)
        port.setValue(6000)
        port.setObjectName("destinationPort")
        duration = QSpinBox()
        duration.setRange(1, 86400)
        duration.setValue(30)
        duration.setObjectName("captureDuration")
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
        capture_form.addRow("Capture interface", interface)
        capture_form.addRow("Destination IP (optional)", destination)
        capture_form.addRow("Destination TCP port", port)
        capture_form.addRow("Observation duration (seconds)", duration)
        capture_form.addRow("PCAP file (replay mode)", pcap_row)
        capture_layout.addLayout(capture_form)
        capture_payload = QCheckBox("Retain payload preview in the local session")
        capture_payload.setAccessibleDescription(
            "Off by default. Reports redact captured payload previews."
        )
        capture_layout.addWidget(capture_payload)
        capture_layout.addWidget(
            QLabel("Payload preview is optional and remains local. Reports redact payload fields by default.")
        )
        capture_layout.addStretch()
        wizard.addTab(capture_page, "2 - Capture")

        review = QWidget()
        review_layout = QVBoxLayout(review)
        review_layout.addWidget(QLabel("Review before starting"))
        review_text = QLabel(
            "Capture records matching TCP metadata and workflow evidence. A missing packet is inconclusive; it does not prove a firewall or remote service caused the issue."
        )
        review_text.setWordWrap(True)
        review_layout.addWidget(review_text)
        review_layout.addStretch()
        wizard.addTab(review, "3 - Review")
        layout.addWidget(wizard)

        navigation = QHBoxLayout()
        previous = QPushButton("Back")
        next_button = QPushButton("Continue")
        start = QPushButton("Create and start diagnostic")
        start.setObjectName("startDiagnostic")
        start.setAccessibleName("Create and start diagnostic")
        navigation.addWidget(previous)
        navigation.addWidget(next_button)
        navigation.addStretch()
        navigation.addWidget(start)
        layout.addLayout(navigation)
        status = QTextEdit()
        status.setReadOnly(True)
        status.setMaximumHeight(100)
        status.setAccessibleName("Diagnostic setup status")
        layout.addWidget(status)

        def update_wizard_controls(index: int) -> None:
            previous.setEnabled(index > 0)
            next_button.setVisible(index < wizard.count() - 1)
            start.setVisible(index == wizard.count() - 1)

        previous.clicked.connect(lambda: wizard.setCurrentIndex(max(0, wizard.currentIndex() - 1)))
        next_button.clicked.connect(lambda: wizard.setCurrentIndex(min(wizard.count() - 1, wizard.currentIndex() + 1)))
        wizard.currentChanged.connect(update_wizard_controls)
        update_wizard_controls(0)

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
                    capture_payload=capture_payload.isChecked(),
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
                replay = Path(pcap.text()) if pcap.text().strip() else None
                if config.mode == DiagnosticMode.PCAP_REPLAY and not replay:
                    raise ValueError("Select a PCAP file for replay mode")
                self.session_id = session_id
                self._start_worker(session_id, config, replay, status)
                self.sidebar.setCurrentRow(6)
                self.update_dashboard(status="Running")
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
        self.worker_thread.finished.connect(self._capture_thread_finished)
        self._track_thread(self.worker_thread)
        self.worker_thread.start()

    @Slot()
    def _capture_thread_finished(self) -> None:
        self.worker = None
        self.worker_thread = None
        self._drain_worker_events()

    def closeEvent(self, event: QCloseEvent) -> None:
        running = [thread for thread in self._threads if thread.isRunning()]
        if running:
            event.ignore()
            if not self._closing:
                self._closing = True
                if self.worker:
                    self.worker.cancel()
                for thread in running:
                    thread.finished.connect(self._finish_close_when_idle)
            return
        event.accept()

    @Slot()
    def _finish_close_when_idle(self) -> None:
        if not any(thread.isRunning() for thread in self._threads):
            self._drain_worker_events()
            QTimer.singleShot(0, self.close)

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
        search = QLineEdit()
        search.setPlaceholderText("Filter session name, status, or ID")
        search.setAccessibleName("Search diagnostic history")
        self.history_search = search
        search.textChanged.connect(self._filter_history)
        layout.addWidget(search)
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Name", "Status", "Created", "Session ID"])
        table.setSortingEnabled(True)
        table.setAccessibleName("Sortable diagnostic session history")
        self.history_table = table
        table.cellDoubleClicked.connect(self._open_history_session)
        layout.addWidget(table)
        return widget

    def _track_thread(self, thread: QThread) -> None:
        self._threads.append(thread)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda current=thread: self._threads.remove(current)
            if current in self._threads
            else None
        )

    def _start_history_load(self) -> None:
        thread = QThread(self)
        loader = SessionHistoryLoader(self.repository)
        loader.moveToThread(thread)
        thread.started.connect(loader.run)
        loader.loaded.connect(self._populate_history)
        loader.failed.connect(self._history_failed)
        loader.loaded.connect(thread.quit)
        loader.failed.connect(thread.quit)
        thread.finished.connect(loader.deleteLater)
        self._track_thread(thread)
        thread.start()

    @Slot(object)
    def _populate_history(self, sessions: object) -> None:
        self.history_table.setSortingEnabled(False)
        self.history_table.setRowCount(0)
        for session in sessions if isinstance(sessions, list) else []:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            for col, key in enumerate(("name", "status", "created_at", "id")):
                self.history_table.setItem(row, col, QTableWidgetItem(str(session.get(key, ""))))
        self.history_table.setSortingEnabled(True)
        self._filter_history(self.history_search.text())

    @Slot(str)
    def _history_failed(self, message: str) -> None:
        self.dashboard_explanation.setText(f"Session history could not be loaded: {message}")

    def _filter_history(self, text: str) -> None:
        table = getattr(self, "history_table", None)
        if table is None:
            return
        query = text.casefold().strip()
        for row in range(table.rowCount()):
            row_text = " ".join(
                table.item(row, col).text()
                for col in range(table.columnCount())
                if table.item(row, col)
            ).casefold()
            table.setRowHidden(row, bool(query and query not in row_text))

    def _open_history_session(self, row: int, _column: int) -> None:
        item = self.history_table.item(row, 3)
        if item is None:
            return
        thread = QThread(self)
        loader = SessionBundleLoader(self.repository, item.text())
        loader.moveToThread(thread)
        thread.started.connect(loader.run)
        loader.loaded.connect(self._display_session_bundle)
        loader.failed.connect(self._history_failed)
        loader.loaded.connect(thread.quit)
        loader.failed.connect(thread.quit)
        thread.finished.connect(loader.deleteLater)
        self._track_thread(thread)
        thread.start()

    @Slot(str, object, object)
    def _display_session_bundle(
        self, session_id: str, config: DiagnosticConfig, bundle: object
    ) -> None:
        self.session_id = session_id
        if isinstance(bundle, dict):
            self.details.load_bundle(session_id, config, bundle)
        self.sidebar.setCurrentRow(6)
        self.update_dashboard(status="Completed")

    def _details_page(self) -> "SessionDetails":
        return SessionDetails(self.repository)

    def _inspection_page(self, title: str, text: str) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel(f"<h2>{title}</h2>"))
        output = QTextEdit(text)
        output.setReadOnly(True)
        output.setAccessibleName(f"{title} inspection results")
        self._inspection_outputs[len(self._inspection_outputs) + 3] = output
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
            f"{r.address_family or 'IP'} {r.destination} via {r.gateway or '-'} "
            f"dev {r.interface or '-'} (index {r.interface_index or '-'}) "
            f"metric {r.metric if r.metric is not None else '-'}"
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
        self._tcp_sessions: dict[str, TCPSession] = {}
        self._first_packet_time: datetime | None = None
        self._paths: dict[str, Path] = {}
        layout = QVBoxLayout(self)
        self.title = QLabel("<h2>Session Details</h2>")
        layout.addWidget(self.title)
        self.status_label = QLabel("Ready to start")
        self.status_label.setAccessibleName("Diagnostic status explanation")
        layout.addWidget(self.status_label)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("Diagnostic workflow progress")
        layout.addWidget(self.progress)
        controls = QHBoxLayout()
        self.stop = QPushButton("Cancel")
        self.export = QPushButton("Open JSON report")
        self.executive_report_button = QPushButton("Open executive report")
        self.technical_report_button = QPushButton("Open technical report")
        self.stop.setAccessibleName("Cancel diagnostic capture")
        self.stop.clicked.connect(self._cancel)
        self.export.clicked.connect(lambda: self._open_report("json"))
        self.executive_report_button.clicked.connect(lambda: self._open_report("executive"))
        self.technical_report_button.clicked.connect(lambda: self._open_report("technical"))
        controls.addWidget(self.stop)
        controls.addWidget(self.export)
        controls.addWidget(self.executive_report_button)
        controls.addWidget(self.technical_report_button)
        controls.addStretch()
        layout.addLayout(controls)
        self.report_paths_label = QLabel("Reports are created after analysis completes.")
        self.report_paths_label.setWordWrap(True)
        layout.addWidget(self.report_paths_label)
        self.tabs = QTabWidget()
        self.overview = QTextEdit()
        self.overview.setReadOnly(True)
        self.workflow = QTextEdit()
        self.workflow.setReadOnly(True)
        self.steps_tree = QTreeWidget()
        self.steps_tree.setHeaderLabels(["Diagnosis step", "Execution status"])
        self.steps_tree.setAccessibleName("Expandable diagnostic steps and explanations")
        self.connections = QTableWidget(0, 9)
        self.connections.setHorizontalHeaderLabels(
            ["Client", "Server", "Observed state", "First seen", "Last seen", "C-to-S bytes", "S-to-C bytes", "Retx", "Dup ACKs"]
        )
        self.connections.setAccessibleName("Interactive TCP session summaries")
        self.connections.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.connections.itemSelectionChanged.connect(self._select_connection)
        self.timeline = QTableWidget(0, 9)
        self.timeline.setHorizontalHeaderLabels(
            ["Timestamp", "Relative", "Source", "Destination", "Flags", "Seq", "Ack", "Payload", "Session"]
        )
        self.timeline.setSortingEnabled(True)
        self.timeline.setAccessibleName("Searchable, sortable TCP packet timeline")
        self.timeline.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline.itemSelectionChanged.connect(self._show_selected_packet)
        self.timeline_search = QLineEdit()
        self.timeline_search.setPlaceholderText("Search addresses, flags, sequence or session")
        self.timeline_search.setAccessibleName("Search packet timeline")
        self.timeline_search.textChanged.connect(self._filter_timeline)
        self.packet_inspector = QTextEdit()
        self.packet_inspector.setReadOnly(True)
        self.packet_inspector.setAccessibleName("Selected packet details")
        timeline_widget = QWidget()
        timeline_layout = QVBoxLayout(timeline_widget)
        timeline_layout.addWidget(self.timeline_search)
        timeline_split = QSplitter(Qt.Orientation.Vertical)
        timeline_split.addWidget(self.timeline)
        timeline_split.addWidget(self.packet_inspector)
        timeline_split.setStretchFactor(0, 4)
        timeline_split.setStretchFactor(1, 1)
        timeline_layout.addWidget(timeline_split)
        self.flow = TCPFlowDiagram()
        flow_tab = QWidget()
        flow_layout = QVBoxLayout(flow_tab)
        flow_layout.addWidget(self.flow)
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
            ("Diagnosis Steps", self.steps_tree),
            ("Live Connections", self.connections),
            ("TCP Flow", flow_tab),
            ("TCP Timeline", timeline_widget),
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
        self._tcp_sessions.clear()
        self._first_packet_time = None
        self._paths.clear()
        self.progress.setValue(0)
        self.overview.setPlainText(f"Session {session_id}\nMode: {config.mode}\nStarting workflow...")
        self.title.setText(f"<h2>Diagnostic session - {config.name}</h2>")
        self.status_label.setText("Starting capture setup. No network health conclusion has been made yet.")
        self.workflow.clear()
        self.steps_tree.clear()
        self.connections.setRowCount(0)
        self.timeline.setRowCount(0)
        self.packet_inspector.clear()
        self.flow.set_session(None)
        self.payload.clear()
        self.evidence.clear()
        self.findings.clear()
        self.report.clear()
        self.report_paths_label.setText("Reports are created after analysis completes.")
        self.stop.setEnabled(True)
        for button in (self.export, self.executive_report_button, self.technical_report_button):
            button.setEnabled(False)

    def load_bundle(
        self, session_id: str, config: DiagnosticConfig, bundle: dict[str, list[dict[str, object]]]
    ) -> None:
        self.reset_view(session_id, config)
        self.progress.setValue(100)
        self.overview.setPlainText(
            f"Reopened session {session_id}\nMode: {config.mode}\nStored evidence loaded."
        )
        for packet in bundle["packets"]:
            self._append_packet_record(packet, str(packet.get("tcp_session_id", "")))
        for raw_session in bundle.get("tcp_sessions", []):
            try:
                session = TCPSession.model_validate(raw_session)
            except (TypeError, ValueError):
                continue
            self._tcp_sessions[session.id] = session
        self._render_connections()
        if self._tcp_sessions:
            self.flow.set_session(next(iter(self._tcp_sessions.values())))
        reports = bundle.get("reports", [])
        for item in reports if isinstance(reports, list) else []:
            html_path = Path(str(item.get("html_path", "")))
            json_path = Path(str(item.get("json_path", "")))
            if "executive" in html_path.stem:
                self._paths["executive"] = html_path
            else:
                self._paths["technical"] = html_path
            self._paths["json"] = json_path
        for key, button in (
            ("json", self.export),
            ("executive", self.executive_report_button),
            ("technical", self.technical_report_button),
        ):
            button.setEnabled(key in self._paths and self._paths[key].is_file())
        self.report_paths_label.setText(
            "\n".join(f"{key.title()}: {path}" for key, path in self._paths.items())
            or "No saved report paths were found for this session."
        )
        for step in bundle.get("steps", []):
            self._update_step_tree(step)
        for finding in bundle["findings"]:
            self.findings.append(self._format_finding(finding))

    def _append_packet_record(
        self, packet: PacketEvent | dict[str, Any], session_id: str = ""
    ) -> None:
        if isinstance(packet, dict):
            getter = packet.get
            timestamp = packet.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    timestamp = None
        else:
            timestamp = packet.timestamp

            def getter(key: str, default: Any = None) -> Any:
                return getattr(packet, key, default)

        if self._first_packet_time is None and timestamp is not None:
            self._first_packet_time = timestamp
        relative = "-"
        if isinstance(timestamp, datetime) and self._first_packet_time is not None:
            relative = f"{(timestamp - self._first_packet_time).total_seconds():.3f}s"
        src = str(getter("src_ip", "?")) + ":" + str(getter("src_port", "?"))
        dst = str(getter("dst_ip", "?")) + ":" + str(getter("dst_port", "?"))
        values = [
            timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp or "-"),
            relative,
            src,
            dst,
            str(getter("flags", "-")),
            str(getter("sequence", "-")),
            str(getter("acknowledgement", "-")),
            str(getter("payload_length", 0)),
            session_id or str(getter("packet_number", "-")),
        ]
        self.timeline.setSortingEnabled(False)
        row = self.timeline.rowCount()
        self.timeline.insertRow(row)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, packet)
            self.timeline.setItem(row, col, item)
        self.timeline.setSortingEnabled(True)

    def _filter_timeline(self, text: str) -> None:
        query = text.casefold().strip()
        for row in range(self.timeline.rowCount()):
            row_text = " ".join(
                cell.text()
                for col in range(self.timeline.columnCount())
                if (cell := self.timeline.item(row, col)) is not None
            ).casefold()
            self.timeline.setRowHidden(row, bool(query and query not in row_text))

    def _show_selected_packet(self) -> None:
        selected = self.timeline.selectedItems()
        item = self.timeline.item(selected[0].row(), 0) if selected else None
        raw_packet = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if isinstance(raw_packet, PacketEvent):
            packet = raw_packet
        elif isinstance(raw_packet, dict):
            try:
                packet = PacketEvent.model_validate(raw_packet)
            except (TypeError, ValueError):
                return
        else:
            return
        fields = (
            ("Timestamp", packet.timestamp),
            ("Capture interface", packet.capture_interface),
            ("Source", f"{packet.src_ip}:{packet.src_port}"),
            ("Destination", f"{packet.dst_ip}:{packet.dst_port}"),
            ("Flags", packet.flags),
            ("Sequence / acknowledgment", f"{packet.sequence} / {packet.acknowledgement}"),
            ("Payload bytes", packet.payload_length),
            ("Payload preview (hex)", packet.payload_preview_hex),
        )
        self.packet_inspector.setPlainText(
            "\n".join(f"{name}: {value}" for name, value in fields if value is not None)
        )

    def _update_step_tree(self, step: DiagnosticStep | dict[str, Any]) -> None:
        if isinstance(step, dict):
            value = step
        elif isinstance(step, DiagnosticStep):
            value = step.model_dump(mode="json")
        else:
            return
        step_id = str(value.get("step_id", "step"))
        item: QTreeWidgetItem | None = None
        for index in range(self.steps_tree.topLevelItemCount()):
            candidate = self.steps_tree.topLevelItem(index)
            if candidate is not None and candidate.data(0, Qt.ItemDataRole.UserRole) == step_id:
                item = candidate
                break
        if item is None:
            item = QTreeWidgetItem([str(value.get("name", step_id)), str(value.get("status", "pending"))])
            item.setData(0, Qt.ItemDataRole.UserRole, step_id)
            self.steps_tree.addTopLevelItem(item)
        else:
            item.setText(1, str(value.get("status", "pending")))
        while item.childCount():
            item.takeChild(0)
        for label, key in (
            ("Purpose", "purpose"),
            ("Explanation", "explanation"),
            ("Confidence", "confidence"),
            ("Evidence references", "evidence_ids"),
            ("Recommended verification", "recommended_verification"),
            ("Next action", "next_action"),
            ("Error details", "error"),
        ):
            detail = value.get(key)
            if detail:
                item.addChild(QTreeWidgetItem([label, str(detail)]))
        item.setExpanded(True)

    @staticmethod
    def _format_finding(finding: Finding | dict[str, Any]) -> str:
        if isinstance(finding, dict):
            value = finding
        elif isinstance(finding, Finding):
            value = finding.model_dump(mode="json")
        else:
            return str(finding)
        return (
            f"[{value.get('severity', 'info')}] {value.get('code', 'finding')} | "
            f"{value.get('confidence', 'inconclusive')}\n{value.get('conclusion', '')}\n"
            f"Evidence: {value.get('supporting_evidence_ids', [])}\n"
            f"Alternatives: {value.get('alternatives', [])}\n"
            f"Limitations: {value.get('limitations', [])}\n"
            f"Verify: {value.get('recommended_verification', '')}\n"
            f"Next: {value.get('next_action', '')}\n"
        )

    @Slot(object)
    def consume_event(self, event: WorkflowEvent) -> None:
        self.progress.setValue(event.progress)
        explanation = {
            "running": "In progress",
            "completed": "Complete",
            "passed": "Complete",
            "warning": "Needs review",
            "failed": "Could not complete",
            "cancelled": "Cancelled; partial evidence was retained",
        }.get(event.status, event.status.replace("_", " ").capitalize())
        self.status_label.setText(f"{explanation}: {event.message}")
        self.workflow.append(f"[{explanation}] {event.stage_id}: {event.message}")
        if event.step:
            self._update_step_tree(event.step)
        if event.packet:
            self._append_packet_record(event.packet, event.tcp_session.id if event.tcp_session else "")
            if event.tcp_session:
                connection = event.tcp_session
                self._tcp_sessions[connection.id] = connection
                self._render_connections()
                self.flow.set_session(connection)
                window = self.window()
                if isinstance(window, MainWindow):
                    window.update_dashboard(
                        packet_count=self.timeline.rowCount(),
                        session_count=len(self._tcp_sessions),
                        retransmissions=sum(item.retransmissions for item in self._tcp_sessions.values()),
                    )
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
            self.findings.append(self._format_finding(event.finding))
            window = self.window()
            if isinstance(window, MainWindow):
                window.update_dashboard(findings=self.findings.document().blockCount())

    def _render_connections(self) -> None:
        self.connections.setRowCount(0)
        for session in self._tcp_sessions.values():
            row = self.connections.rowCount()
            self.connections.insertRow(row)
            values = [
                f"{session.client_ip}:{session.client_port}",
                f"{session.server_ip}:{session.server_port}",
                session.observed_state,
                session.first_seen.isoformat(),
                session.last_seen.isoformat(),
                str(session.payload_bytes_client_to_server),
                str(session.payload_bytes_server_to_client),
                str(session.retransmissions),
                str(session.duplicate_acks),
            ]
            for col, value in enumerate(values):
                self.connections.setItem(row, col, QTableWidgetItem(value))
            item = self.connections.item(row, 0)
            if item is not None:
                item.setData(Qt.ItemDataRole.UserRole, session.id)

    def _select_connection(self) -> None:
        selected = self.connections.selectedItems()
        if not selected:
            return
        item = self.connections.item(selected[0].row(), 0)
        session_id = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if session_id in self._tcp_sessions:
            self.flow.set_session(self._tcp_sessions[session_id])

    @Slot(object)
    def finish(self, result: object) -> None:
        self.progress.setValue(100)
        if isinstance(result, dict):
            paths = {
                "technical": result.get("html_report"),
                "executive": result.get("executive_html_report"),
                "json": result.get("json_report"),
            }
            self._paths = {key: Path(value) for key, value in paths.items() if value}
            self.report.setPlainText(
                "Reports verified on disk:\n"
                + "\n".join(f"{key.title()}: {path}" for key, path in self._paths.items())
            )
            self.report_paths_label.setText(self.report.toPlainText())
            for key, button in (
                ("json", self.export),
                ("executive", self.executive_report_button),
                ("technical", self.technical_report_button),
            ):
                button.setEnabled(key in self._paths and self._paths[key].is_file())
            summary = result.get("report", {})
            if isinstance(summary, dict):
                metrics = summary.get("metrics", {})
                if isinstance(metrics, dict):
                    window = self.window()
                    if isinstance(window, MainWindow):
                        window.update_dashboard(**metrics, status="Completed")
        self.status_label.setText("Diagnostic completed. Review the observed evidence and report limitations.")
        self.stop.setEnabled(False)

    def _open_report(self, report_type: str) -> None:
        path = self._paths.get(report_type)
        if path and path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    @Slot(str, object)
    def fail(self, error: str, status: QTextEdit | None = None) -> None:
        self.workflow.append(f"[failed] {error}")
        self.status_label.setText("The diagnostic could not complete. Review the error and retained evidence.")
        if status:
            status.setPlainText(error)
        self.stop.setEnabled(False)

    def _cancel(self) -> None:
        window = self.window()
        if isinstance(window, MainWindow) and window.worker:
            window.worker.cancel()

def run() -> int:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.show()
    return app.exec()
