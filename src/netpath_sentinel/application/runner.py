import asyncio
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from netpath_sentinel.analysis.heartbeat import evaluate_heartbeat
from netpath_sentinel.analysis.rca import analyze
from netpath_sentinel.analysis.tcp import TCPSessionTracker
from netpath_sentinel.domain.enums import EvidenceStatus, StepStatus
from netpath_sentinel.domain.models import (
    DiagnosticConfig,
    DiagnosticStep,
    Evidence,
    Finding,
    PacketEvent,
    TCPSession,
)
from netpath_sentinel.infrastructure.capture import capture_live, replay_pcap
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


EventSink = Callable[[WorkflowEvent], Awaitable[None] | None]


class DiagnosticRunner:
    """Runs replay and live diagnostics through the same normalization/analysis path."""

    def __init__(self, repository: Repository, inspector: HostInspector | None = None) -> None:
        self.repository = repository
        self.inspector = inspector or HostInspector()

    async def run(
        self,
        session_id: str,
        config: DiagnosticConfig,
        sink: EventSink | None = None,
        pcap_path: Path | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> dict[str, object]:
        cancel_event = cancel_event or asyncio.Event()
        self.repository.update_session_status(session_id, "running")
        steps: list[DiagnosticStep] = []

        async def emit(event: WorkflowEvent) -> None:
            if sink:
                result = sink(event)
                if asyncio.iscoroutine(result):
                    await result

        async def stage(stage_id: str, name: str, progress: int) -> DiagnosticStep:
            step = DiagnosticStep(
                session_id=session_id,
                step_id=stage_id,
                name=name,
                status=StepStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            steps.append(step)
            self.repository.save_step(step)
            await emit(WorkflowEvent(session_id, "stage", stage_id, "running", progress, name))
            return step

        async def finish(
            step: DiagnosticStep, status: StepStatus, progress: int, message: str
        ) -> None:
            step.status = status
            step.ended_at = datetime.now(UTC)
            self.repository.save_step(step)
            await emit(
                WorkflowEvent(session_id, "stage", step.step_id, status.value, progress, message)
            )

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
                    "listeners": [listener.model_dump() for listener in snapshot.listeners],
                },
            )
            self.repository.save_evidence(route_evidence)
            step.evidence_ids = [route_evidence.id]
            await emit(WorkflowEvent(session_id, "evidence", "route_inspection", "completed", 20,
                                      "Route and listener snapshot collected", evidence=route_evidence))
            await finish(step, StepStatus.PASSED, 20, "Route and listener inspection complete")

            step = await stage("capture_preparation", "Prepare packet observation", 25)
            if str(config.mode) == "pcap_replay":
                if not pcap_path or not pcap_path.exists():
                    raise FileNotFoundError("PCAP replay mode requires an existing capture file")
                packets: Iterable[PacketEvent] = replay_pcap(pcap_path)
                capture_source = str(pcap_path)
            else:
                interface = config.interface or self._default_interface(snapshot.interfaces)
                if not interface:
                    raise RuntimeError("No capture interface is available")
                active_listener: DiagnosticListener | None = None
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
                try:
                    packets = await asyncio.to_thread(
                        capture_live,
                        interface,
                        config.duration_seconds,
                        config.destination_port,
                        config.max_packets,
                        packet_filter,
                    )
                finally:
                    if active_listener:
                        await active_listener.stop()
                capture_source = f"live:{interface}"
            await finish(step, StepStatus.PASSED, 30, f"Capture ready: {capture_source}")

            tracker = TCPSessionTracker(server_port=config.destination_port)
            step = await stage("packet_observation", "Observe TCP packets", 35)
            if cancel_event.is_set():
                raise asyncio.CancelledError
            packet_count = 0
            for packet in packets:
                if cancel_event.is_set():
                    raise asyncio.CancelledError
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
            summary = Evidence(
                session_id=session_id,
                evidence_type="packet_summary",
                source=capture_source,
                status=EvidenceStatus.OBSERVED if packet_count else EvidenceStatus.NOT_OBSERVED,
                observation={
                    "packets": packet_count,
                    "sessions": len(tracker.sessions),
                    "handshakes": [s.handshake for s in tracker.sessions],
                },
            )
            self.repository.save_evidence(summary)
            step.evidence_ids = [summary.id]
            await emit(WorkflowEvent(session_id, "evidence", "packet_observation", "completed", 85,
                                      "Packet summary collected", evidence=summary))
            await finish(
                step,
                StepStatus.PASSED if packet_count else StepStatus.WARNING,
                85,
                f"Observed {packet_count} TCP packets",
            )

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
            await emit(WorkflowEvent(session_id, "evidence", "heartbeat", "completed", 88,
                                      f"Heartbeat status: {heartbeat['status']}", evidence=heartbeat_evidence))

            step = await stage("rca", "Correlate evidence and diagnose", 90)
            findings = analyze(
                session_id,
                [host_evidence, route_evidence, summary],
                [s.handshake for s in tracker.sessions],
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
            report = self._report_payload(session_id, config, snapshot, tracker.sessions, findings)
            report_dir = Path(self.repository.database_path).parent / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            html_path = export_html(
                report_dir / f"{session_id}.html", "NetPath Sentinel Diagnostic Report", report
            )
            json_path = export_json(report_dir / f"{session_id}.json", report)
            self.repository.save_report(session_id, str(html_path), str(json_path))
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
            self.repository.update_session_status(session_id, "failed")
            await emit(WorkflowEvent(session_id, "error", "workflow", "failed", 100, str(exc)))
            raise

    @staticmethod
    def _default_interface(interfaces: Sequence[object]) -> str | None:
        for item in interfaces:
            name = str(getattr(item, "name", ""))
            if getattr(item, "is_up", False) and name != "lo":
                return name
        return None

    @staticmethod
    def _report_payload(
        session_id: str,
        config: DiagnosticConfig,
        snapshot: HostSnapshot,
        sessions: list[TCPSession],
        findings: list[Finding],
    ) -> dict[str, object]:
        return {
            "session_id": session_id,
            "configuration": config.model_dump(mode="json"),
            "hostname": snapshot.hostname,
            "os": snapshot.os_version,
            "tcp_sessions": [s.model_dump(mode="json", exclude={"packets"}) for s in sessions],
            "findings": [f.model_dump(mode="json") for f in findings],
            "limitations": [
                "Packet capture evidence only describes what was observable at this host."
            ],
        }
