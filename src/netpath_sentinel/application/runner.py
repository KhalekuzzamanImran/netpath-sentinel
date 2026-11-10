import asyncio
import queue
import threading
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

from netpath_sentinel.analysis.heartbeat import evaluate_heartbeat
from netpath_sentinel.analysis.rca import analyze
from netpath_sentinel.analysis.tcp import TCPSessionTracker
from netpath_sentinel.domain.enums import Confidence, EvidenceStatus, StepStatus
from netpath_sentinel.domain.models import (
    DiagnosticConfig,
    DiagnosticStep,
    Evidence,
    Finding,
    PacketEvent,
    TCPSession,
)
from netpath_sentinel.infrastructure.capture import BoundedPacketQueue, capture_live, replay_pcap
from netpath_sentinel.infrastructure.host import HostInspector, HostSnapshot
from netpath_sentinel.infrastructure.listener import DiagnosticListener
from netpath_sentinel.infrastructure.persistence import Repository
from netpath_sentinel.reporting.report import export_html, export_json


@dataclass
class WorkflowEvent:
    session_id: str
    event_type: str
    stage_id: str
    status: str
    progress: int
    message: str
    packet: PacketEvent | None = None
    tcp_session: TCPSession | None = None
    evidence: Evidence | None = None
    finding: Finding | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    step: DiagnosticStep | None = None


EventSink = Callable[[WorkflowEvent], Awaitable[None] | None]


class DiagnosticRunner:
    """Runs replay and live diagnostics through the same normalization/analysis path."""

    def __init__(self, repository: Repository, inspector: HostInspector | None = None) -> None:
        self.repository = repository
        self.inspector = inspector or HostInspector()
        self._active_sessions: set[str] = set()

    async def run(
        self,
        session_id: str,
        config: DiagnosticConfig,
        sink: EventSink | None = None,
        pcap_path: Path | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> dict[str, object]:
        cancel_event = cancel_event or asyncio.Event()
        if session_id in self._active_sessions:
            raise RuntimeError("diagnostic session is already running")
        self._active_sessions.add(session_id)
        self.repository.update_session_status(session_id, "running")
        steps: list[DiagnosticStep] = []
        collected_evidence: list[Evidence] = []
        active_step: DiagnosticStep | None = None
        replay_packet_limit_reached = False

        async def emit(event: WorkflowEvent) -> None:
            if sink:
                result = sink(event)
                if asyncio.iscoroutine(result):
                    await result

        purposes = {
            "host_discovery": "Collect the local host identity and available network adapters.",
            "route_inspection": "Inspect local routes and listening TCP sockets.",
            "capture_preparation": "Validate the selected capture source and wait for readiness.",
            "packet_observation": "Observe matching TCP traffic for this diagnostic window.",
            "heartbeat": "Compare observed activity with the configured heartbeat expectation.",
            "rca": "Correlate captured evidence without attributing an unobserved cause.",
        }

        async def stage(stage_id: str, name: str, progress: int) -> DiagnosticStep:
            nonlocal active_step
            step = DiagnosticStep(
                session_id=session_id,
                step_id=stage_id,
                name=name,
                status=StepStatus.RUNNING,
                purpose=purposes.get(stage_id, name),
                started_at=datetime.now(UTC),
            )
            steps.append(step)
            active_step = step
            self.repository.save_step(step)
            await emit(
                WorkflowEvent(
                    session_id,
                    "stage",
                    stage_id,
                    "running",
                    progress,
                    name,
                    step=step.model_copy(deep=True),
                )
            )
            return step

        async def finish(
            step: DiagnosticStep, status: StepStatus, progress: int, message: str
        ) -> None:
            nonlocal active_step
            step.status = status
            step.ended_at = datetime.now(UTC)
            step.explanation = message
            step.confidence = (
                Confidence.INCONCLUSIVE
                if status in {StepStatus.WARNING, StepStatus.FAILED, StepStatus.INCONCLUSIVE}
                else Confidence.POSSIBLE
            )
            step.recommended_verification = (
                "Review the evidence references attached to this step."
                if status not in {StepStatus.FAILED, StepStatus.WARNING}
                else "Resolve the warning or collection issue, then repeat the affected step."
            )
            step.next_action = (
                "Continue to the next diagnostic step."
                if status == StepStatus.PASSED
                else "Review the limitation and decide whether a repeat capture is needed."
            )
            self.repository.save_step(step)
            await emit(
                WorkflowEvent(
                    session_id,
                    "stage",
                    step.step_id,
                    status.value,
                    progress,
                    message,
                    step=step.model_copy(deep=True),
                )
            )
            if active_step is step:
                active_step = None

        try:
            step = await stage("host_discovery", "Discover host", 5)
            # The runner itself executes on a worker thread in the desktop app;
            # keeping this read-only snapshot synchronous avoids platform psutil
            # backends that do not behave well when invoked from executor threads.
            snapshot = self.inspector.snapshot()
            host_evidence = Evidence(
                session_id=session_id,
                evidence_type="host_snapshot",
                source="host_inspector",
                status=EvidenceStatus.OBSERVED,
                observation={
                    "hostname": snapshot.hostname,
                    "os": snapshot.os_version,
                    "interfaces": [i.model_dump() for i in snapshot.interfaces],
                },
            )
            self.repository.save_evidence(host_evidence)
            collected_evidence.append(host_evidence)
            step.evidence_ids = [host_evidence.id]
            await emit(WorkflowEvent(session_id, "evidence", "host_discovery", "completed", 10,
                                      "Host snapshot collected", evidence=host_evidence))
            await finish(step, StepStatus.PASSED, 10, "Host discovery complete")

            step = await stage("route_inspection", "Inspect routes and listeners", 15)
            route_evidence = Evidence(
                session_id=session_id,
                evidence_type="route_snapshot",
                source="host_inspector",
                status=EvidenceStatus.OBSERVED,
                observation={
                    "routes": [r.model_dump() for r in snapshot.routes],
                    "route_error": snapshot.route_error,
                    "listeners": [listener.model_dump() for listener in snapshot.listeners],
                },
            )
            self.repository.save_evidence(route_evidence)
            collected_evidence.append(route_evidence)
            step.evidence_ids = [route_evidence.id]
            await emit(WorkflowEvent(session_id, "evidence", "route_inspection", "completed", 20,
                                      "Route and listener snapshot collected", evidence=route_evidence))
            await finish(step, StepStatus.PASSED, 20, "Route and listener inspection complete")

            step = await stage("capture_preparation", "Prepare packet observation", 25)
            live_queue: BoundedPacketQueue | None = None
            capture_task: asyncio.Task[Iterable[PacketEvent]] | None = None
            stop_capture: threading.Event | None = None
            capture_ready: threading.Event | None = None
            active_listener: DiagnosticListener | None = None
            if str(config.mode) == "pcap_replay":
                if not pcap_path or not pcap_path.exists():
                    raise FileNotFoundError("PCAP replay mode requires an existing capture file")
                if pcap_path.stat().st_size > config.max_capture_bytes:
                    raise ValueError("PCAP exceeds configured maximum capture size")
                source_packets = replay_pcap(pcap_path, capture_payload=config.capture_payload)

                def bounded_replay() -> Iterable[PacketEvent]:
                    nonlocal replay_packet_limit_reached
                    for index, packet in enumerate(source_packets):
                        if index >= config.max_packets:
                            replay_packet_limit_reached = True
                            break
                        yield packet

                packets: Iterable[PacketEvent] = bounded_replay()
                capture_source = str(pcap_path)
            else:
                interface = config.interface or self._default_interface(
                    snapshot.interfaces,
                    config.destination_ip,
                    snapshot.routes,
                )
                if not interface:
                    raise RuntimeError(
                        "No unambiguous capture interface is available. Select an adapter explicitly."
                    )
                if str(config.mode) == "active_listener":
                    occupied = [
                        item
                        for item in snapshot.listeners
                        if item.local_port == config.destination_port
                    ]
                    if occupied:
                        process = occupied[0].process or "unknown process"
                        raise RuntimeError(
                            f"port {config.destination_port} is occupied by {process}; passive capture is available"
                        )
                    active_listener = DiagnosticListener("0.0.0.0", config.destination_port)
                    await active_listener.start()
                packet_filter = f"tcp port {config.destination_port}"
                if config.source_ip:
                    packet_filter += f" and host {config.source_ip}"
                stop_capture = threading.Event()
                capture_ready = threading.Event()
                live_queue = BoundedPacketQueue(capacity=512)
                capture_task = asyncio.create_task(asyncio.to_thread(
                    capture_live,
                    interface,
                    config.duration_seconds,
                    config.destination_port,
                    config.max_packets,
                    packet_filter,
                    stop_capture,
                    live_queue,
                    capture_ready,
                    config.capture_payload,
                ))
                while not capture_ready.is_set() and not capture_task.done():
                    if cancel_event.is_set():
                        stop_capture.set()
                    await asyncio.to_thread(capture_ready.wait, 0.05)
                if capture_task.done():
                    await capture_task
                    if not capture_ready.is_set() and not cancel_event.is_set():
                        raise RuntimeError("Capture backend stopped before it became ready.")
                packets = ()
                capture_source = f"live:{interface}"
            await finish(
                step,
                StepStatus.WARNING if cancel_event.is_set() and capture_ready and not capture_ready.is_set() else StepStatus.PASSED,
                30,
                "Capture cancelled before readiness; partial host evidence was retained."
                if cancel_event.is_set() and capture_ready and not capture_ready.is_set()
                else f"Capture ready: {capture_source}",
            )

            tracker = TCPSessionTracker(server_port=config.destination_port)
            step = await stage("packet_observation", "Observe TCP packets", 35)
            packet_count = 0
            async def consume_packet(packet: PacketEvent) -> None:
                nonlocal packet_count
                packet_count += 1
                session = tracker.ingest(packet)
                self.repository.save_packet(packet, session.id, session_id)
                self.repository.save_tcp_session(session, session_id)
                await emit(
                    WorkflowEvent(
                        session_id,
                        "packet",
                        "packet_observation",
                        "running",
                        min(85, 35 + packet_count % 50),
                        f"Observed packet {packet_count}",
                        packet=packet,
                        tcp_session=session,
                    )
                )
            try:
                if capture_task is not None and live_queue is not None:
                    while not capture_task.done() or not live_queue.empty():
                        if cancel_event.is_set() and stop_capture is not None:
                            stop_capture.set()
                        try:
                            packet = await asyncio.to_thread(live_queue.get, 0.1)
                        except queue.Empty:
                            continue
                        await consume_packet(packet)
                    await capture_task
                else:
                    for packet in packets:
                        await consume_packet(packet)
            finally:
                if stop_capture is not None:
                    stop_capture.set()
                if capture_task is not None and not capture_task.done():
                    await asyncio.shield(capture_task)
                if active_listener:
                    await active_listener.stop()
            summary = Evidence(
                session_id=session_id,
                evidence_type="packet_summary",
                source=capture_source,
                status=(
                    EvidenceStatus.INCOMPLETE
                    if cancel_event.is_set() or replay_packet_limit_reached
                    else EvidenceStatus.OBSERVED
                    if packet_count
                    else EvidenceStatus.NOT_OBSERVED
                ),
                observation={
                    "packets": packet_count,
                    "sessions": len(tracker.sessions),
                    "handshakes": [s.handshake for s in tracker.sessions],
                    "internal_queue_drops": live_queue.dropped if live_queue else 0,
                    "capture_complete": not cancel_event.is_set() and not replay_packet_limit_reached,
                    "packet_limit_reached": replay_packet_limit_reached,
                },
            )
            self.repository.save_evidence(summary)
            collected_evidence.append(summary)
            step.evidence_ids = [summary.id]
            await emit(WorkflowEvent(session_id, "evidence", "packet_observation", "completed", 85,
                                      "Packet summary collected", evidence=summary))
            await finish(
                step,
                StepStatus.WARNING
                if cancel_event.is_set() or replay_packet_limit_reached or not packet_count
                else StepStatus.PASSED,
                85,
                f"Observed {packet_count} TCP packets"
                + (" before cancellation" if cancel_event.is_set() else "")
                + ("; replay stopped at configured packet limit" if replay_packet_limit_reached else ""),
            )
            if cancel_event.is_set():
                raise asyncio.CancelledError

            step = await stage("heartbeat", "Evaluate heartbeat", 88)
            last_packet = tracker.sessions[-1].last_seen if tracker.sessions else None
            heartbeat = evaluate_heartbeat(
                last_packet,
                None,
                datetime.now(UTC),
                config.expected_heartbeat_interval,
                config.heartbeat_timeout,
                config.heartbeat_mode,
            )
            heartbeat_evidence = Evidence(
                session_id=session_id,
                evidence_type="heartbeat_status",
                source="heartbeat_evaluator",
                status=EvidenceStatus.OBSERVED,
                observation=heartbeat,
            )
            self.repository.save_evidence(heartbeat_evidence)
            collected_evidence.append(heartbeat_evidence)
            step.evidence_ids = [heartbeat_evidence.id]
            await emit(WorkflowEvent(session_id, "evidence", "heartbeat", "completed", 88,
                                      f"Heartbeat status: {heartbeat['status']}", evidence=heartbeat_evidence))
            await finish(step, StepStatus.PASSED, 89, f"Heartbeat status: {heartbeat['status']}")

            step = await stage("rca", "Correlate evidence and diagnose", 90)
            findings = analyze(
                session_id,
                collected_evidence,
                [s.handshake for s in tracker.sessions],
                tracker.sessions,
            )
            for finding in findings:
                self.repository.save_finding(finding)
                await emit(
                    WorkflowEvent(
                        session_id,
                        "finding",
                        "rca",
                        "completed",
                        95,
                        finding.conclusion,
                        finding=finding,
                    )
                )
            await finish(step, StepStatus.PASSED, 95, f"Generated {len(findings)} findings")
            report = self._report_payload(
                session_id,
                config,
                snapshot,
                tracker.sessions,
                findings,
                steps,
                collected_evidence,
            )
            report_dir = Path(self.repository.database_path).parent / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            html_path = export_html(
                report_dir / f"{session_id}.html",
                "NetPath Sentinel Diagnostic Report",
                report,
                report_kind="technical",
            )
            executive_html_path = export_html(
                report_dir / f"{session_id}-executive.html",
                "NetPath Sentinel Executive Summary",
                report,
                report_kind="executive",
            )
            json_path = export_json(report_dir / f"{session_id}.json", report)
            if not html_path.is_file() or html_path.stat().st_size == 0:
                raise OSError(f"HTML report was not persisted: {html_path}")
            if not json_path.is_file() or json_path.stat().st_size == 0:
                raise OSError(f"JSON report was not persisted: {json_path}")
            if not executive_html_path.is_file() or executive_html_path.stat().st_size == 0:
                raise OSError(f"Executive report was not persisted: {executive_html_path}")
            self.repository.save_report(session_id, str(html_path), str(json_path))
            self.repository.save_report(session_id, str(executive_html_path), str(json_path))
            self.repository.update_session_status(session_id, "completed")
            await emit(
                WorkflowEvent(
                    session_id,
                    "complete",
                    "report",
                    "completed",
                    100,
                    "Diagnostic report generated",
                )
            )
            return {
                "sessions": tracker.sessions,
                "findings": findings,
                "report": report,
                "html_report": html_path,
                "executive_html_report": executive_html_path,
                "json_report": json_path,
            }
        except asyncio.CancelledError:
            self.repository.update_session_status(session_id, "cancelled")
            await emit(
                WorkflowEvent(
                    session_id, "complete", "cancelled", "cancelled", 100, "Diagnostic cancelled"
                )
            )
            raise
        except Exception as exc:
            diagnostics = getattr(exc, "diagnostics", {})
            if not isinstance(diagnostics, dict):
                diagnostics = {}
            failure_evidence = Evidence(
                session_id=session_id,
                evidence_type="capture_error",
                source="capture_backend",
                status=(
                    EvidenceStatus.PERMISSION_DENIED
                    if diagnostics.get("error_category") == "permission_denied"
                    else EvidenceStatus.COLLECTION_FAILED
                ),
                observation={
                    "error_category": diagnostics.get("error_category", "capture_failed"),
                    "error": str(exc),
                    "diagnostics": diagnostics,
                    "selected_interface": config.interface,
                    "capture_incomplete": True,
                },
            )
            self.repository.save_evidence(failure_evidence)
            collected_evidence.append(failure_evidence)
            if active_step is not None:
                active_step.status = (
                    StepStatus.PERMISSION_DENIED
                    if failure_evidence.status == EvidenceStatus.PERMISSION_DENIED
                    else StepStatus.FAILED
                )
                active_step.ended_at = datetime.now(UTC)
                active_step.error = str(exc)
                active_step.explanation = "Capture setup or collection did not complete; no network-health conclusion is supported by this error alone."
                active_step.confidence = Confidence.INCONCLUSIVE
                active_step.evidence_ids.append(failure_evidence.id)
                active_step.recommended_verification = "Review the capture diagnostic category, selected interface, and user permissions."
                active_step.next_action = "Correct the capture setup and retry with an authorized adapter."
                self.repository.save_step(active_step)
                await emit(
                    WorkflowEvent(
                        session_id,
                        "stage",
                        active_step.step_id,
                        active_step.status.value,
                        100,
                        active_step.explanation,
                        evidence=failure_evidence,
                        step=active_step.model_copy(deep=True),
                    )
                )
            if not any(item.evidence_type == "packet_summary" for item in collected_evidence):
                for finding in analyze(session_id, collected_evidence, []):
                    self.repository.save_finding(finding)
                    await emit(
                        WorkflowEvent(
                            session_id,
                            "finding",
                            "rca",
                            "completed",
                            95,
                            finding.conclusion,
                            finding=finding,
                        )
                    )
            self.repository.update_session_status(session_id, "failed")
            await emit(WorkflowEvent(session_id, "error", "workflow", "failed", 100, str(exc)))
            raise
        finally:
            self._active_sessions.discard(session_id)

    @staticmethod
    def _default_interface(
        interfaces: Sequence[object],
        destination: object | None = None,
        routes: Sequence[object] = (),
    ) -> str | None:
        active = {
            str(getattr(item, "name", "")): item
            for item in interfaces
            if getattr(item, "is_up", False) and getattr(item, "name", "")
        }
        if destination:
            try:
                target = ip_address(str(destination))
            except ValueError:
                target = None
            if target and target.is_loopback:
                loopbacks = [
                    name
                    for name in active
                    if "loopback" in name.casefold() or name.casefold() == "lo"
                ]
                return loopbacks[0] if len(loopbacks) == 1 else None
        else:
            target = None

        matching: list[tuple[int, int, str]] = []
        for route in routes:
            name = str(getattr(route, "interface", "") or "")
            if name not in active:
                continue
            try:
                network = ip_network(str(getattr(route, "destination", "")), strict=False)
            except ValueError:
                continue
            if target and (network.version != target.version or target not in network):
                continue
            if target is None and network.prefixlen != 0:
                continue
            metric_value = getattr(route, "metric", None)
            metric = metric_value if isinstance(metric_value, int) else 2**31 - 1
            matching.append((network.prefixlen, metric, name))
        if matching:
            best_prefix = max(entry[0] for entry in matching)
            best_metric = min(entry[1] for entry in matching if entry[0] == best_prefix)
            choices = {
                entry[2]
                for entry in matching
                if entry[0] == best_prefix and entry[1] == best_metric
            }
            return next(iter(choices)) if len(choices) == 1 else None

        non_loopback = [
            name for name in active if name.casefold() not in {"lo", "loopback pseudo-interface 1"}
        ]
        return non_loopback[0] if len(non_loopback) == 1 else None

    @staticmethod
    def _report_payload(
        session_id: str,
        config: DiagnosticConfig,
        snapshot: HostSnapshot,
        sessions: list[TCPSession],
        findings: list[Finding],
        steps: list[DiagnosticStep] | None = None,
        evidence: list[Evidence] | None = None,
    ) -> dict[str, object]:
        packet_events = [packet for session in sessions for packet in session.packets]
        retransmissions = sum(session.retransmissions for session in sessions)
        return {
            "session_id": session_id,
            "configuration": config.model_dump(mode="json"),
            "hostname": snapshot.hostname,
            "os": snapshot.os_version,
            "interfaces": [interface.model_dump(mode="json") for interface in snapshot.interfaces],
            "routes": [route.model_dump(mode="json") for route in snapshot.routes],
            "route_error": snapshot.route_error,
            "listeners": [listener.model_dump(mode="json") for listener in snapshot.listeners],
            "tcp_sessions": [s.model_dump(mode="json", exclude={"packets"}) for s in sessions],
            "findings": [f.model_dump(mode="json") for f in findings],
            "steps": [step.model_dump(mode="json") for step in steps or []],
            "evidence": [item.model_dump(mode="json") for item in evidence or []],
            "packet_timeline": [packet.model_dump(mode="json") for packet in packet_events],
            "metrics": {
                "tcp_sessions": len(sessions),
                "packets_observed": len(packet_events),
                "retransmissions": retransmissions,
                "findings": len(findings),
            },
            "limitations": [
                "Packet capture evidence only describes what was observable at this host."
            ],
        }
