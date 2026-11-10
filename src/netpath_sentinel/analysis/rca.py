from collections.abc import Sequence

from netpath_sentinel.domain.enums import Confidence, Severity
from netpath_sentinel.domain.models import Evidence, Finding, TCPSession


def _finding(
    session_id: str,
    code: str,
    conclusion: str,
    evidence_ids: list[str],
    *,
    confidence: Confidence = Confidence.POSSIBLE,
    severity: Severity = Severity.INFO,
    alternatives: list[str] | None = None,
    verification: str,
    next_action: str,
    limitations: list[str] | None = None,
) -> Finding:
    return Finding(
        session_id=session_id,
        code=code,
        severity=severity,
        conclusion=conclusion,
        confidence=confidence,
        supporting_evidence_ids=evidence_ids,
        alternatives=alternatives or [],
        limitations=limitations or [
            "Packet evidence describes only what was observable at this capture point."
        ],
        recommended_verification=verification,
        next_action=next_action,
    )


def analyze(
    session_id: str,
    evidence: list[Evidence],
    tcp_handshakes: Sequence[str],
    sessions: Sequence[TCPSession] = (),
) -> list[Finding]:
    findings: list[Finding] = []
    packet = next((item for item in evidence if item.evidence_type == "packet_summary"), None)
    capture_error = next((item for item in evidence if item.evidence_type == "capture_error"), None)
    ids = [item.id for item in evidence]
    if packet is None:
        if capture_error is not None:
            category = str(capture_error.observation.get("error_category", "capture_failed"))
            code = "CAPTURE_PERMISSION_DENIED" if category == "permission_denied" else "CAPTURE_FAILED"
            reason = str(capture_error.observation.get("error", "Capture failed."))
            return [
                _finding(
                    session_id,
                    code,
                    f"Packet capture did not complete: {reason}. No network-health conclusion is supported.",
                    [capture_error.id],
                    confidence=Confidence.INCONCLUSIVE,
                    severity=Severity.MEDIUM,
                    alternatives=[
                        "The selected adapter may not support this capture backend.",
                        "The capture driver, filter, or user permissions may be unavailable.",
                    ],
                    verification="Review the structured capture diagnostic category and confirm the selected interface mapping.",
                    next_action="Resolve the capture setup issue and repeat the diagnostic before interpreting traffic absence.",
                )
            ]
        return [
            _finding(
                session_id,
                "NO_PACKET_EVIDENCE",
                "TCP packets were not collected, so this run cannot support a network conclusion.",
                ids,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.MEDIUM,
                alternatives=["Capture was unavailable or failed before packet observation."],
                verification="Review the capture setup result and selected interface.",
                next_action="Correct the capture setup and repeat while generating a controlled connection.",
            )
        ]

    observed = int(packet.observation.get("packets", 0) or 0)
    complete_capture = bool(packet.observation.get("capture_complete", True))
    packet_confidence = Confidence.POSSIBLE if complete_capture else Confidence.INCONCLUSIVE
    if not observed:
        code = "NO_PACKETS_OBSERVED" if complete_capture else "CAPTURE_INCOMPLETE_NO_PACKETS"
        conclusion = (
            "No matching TCP packets were observed during the capture window. This does not establish that no connection was attempted."
            if complete_capture
            else "The capture ended before matching TCP packets were observed; no connection conclusion is supported."
        )
        findings.append(
            _finding(
                session_id,
                code,
                conclusion,
                [packet.id],
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.MEDIUM if complete_capture else Severity.INFO,
                alternatives=[
                    "The source did not attempt a connection during this window.",
                    "The selected interface, filter, or capture point did not observe the flow.",
                    "The capture may have ended or dropped packets before they reached the analyzer.",
                ],
                verification="Confirm the destination, port, filter, and interface while generating a controlled connection.",
                next_action="Repeat during a known connection attempt and compare source and destination socket observations.",
                limitations=[
                    "Absence of packets at this capture point does not identify a firewall, router, ISP, or remote application as the cause."
                ],
            )
        )
        return findings

    states = set(tcp_handshakes)
    support_ids = [packet.id]
    if "reset" in states or any(item.observed_state == "reset_observed" for item in sessions):
        findings.append(
            _finding(
                session_id,
                "TCP_RESET_OBSERVED",
                "A TCP reset (RST) packet was observed for a matching flow.",
                support_ids,
                confidence=Confidence.CONFIRMED,
                severity=Severity.MEDIUM,
                alternatives=["The endpoint application or TCP stack actively rejected or aborted the flow."],
                verification="Inspect the RST source endpoint and correlate it with the local socket and application logs.",
                next_action="Verify whether the reset was expected for this connection attempt.",
            )
        )
    elif any(item.capture_started_midstream for item in sessions) or "not_observed_midstream" in states:
        findings.append(
            _finding(
                session_id,
                "MIDSTREAM_CAPTURE",
                "The capture began after a TCP connection was already in progress; its handshake was not observed.",
                support_ids,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                alternatives=["The connection may have started before capture readiness."],
                verification="Start capture before opening the connection.",
                next_action="Repeat the test from before SYN until connection termination.",
            )
        )
    elif "complete" in states:
        findings.append(
            _finding(
                session_id,
                "TCP_HANDSHAKE_COMPLETE",
                "A sequence-validated TCP three-way handshake was observed.",
                support_ids,
                confidence=Confidence.CONFIRMED,
                severity=Severity.INFO,
                alternatives=["A successful handshake does not by itself prove the application exchange succeeded."],
                verification="Check payload exchange and application-level response after the handshake.",
                next_action="Review payload byte counts, heartbeat evidence, and termination state.",
            )
        )
        if sessions and all(
            item.payload_bytes_client_to_server == 0
            and item.payload_bytes_server_to_client == 0
            for item in sessions
        ):
            findings.append(
                _finding(
                    session_id,
                    "HANDSHAKE_WITHOUT_PAYLOAD",
                    "The handshake completed, but no TCP payload bytes were observed in either direction.",
                    support_ids,
                    confidence=packet_confidence,
                    severity=Severity.LOW,
                    alternatives=["The application may not send data during the observation window."],
                    verification="Confirm that the client sent application data before capture stopped.",
                    next_action="Repeat with a known payload and verify both endpoint behavior.",
                )
            )
    elif "syn_ack_observed" in states:
        findings.append(
            _finding(
                session_id,
                "SYN_ACK_WITHOUT_FINAL_ACK",
                "A SYN and SYN-ACK were observed, but a valid final ACK was not captured.",
                support_ids,
                confidence=packet_confidence,
                severity=Severity.MEDIUM,
                alternatives=[
                    "The final ACK may have been lost, outside this capture point, or captured with insufficient context."
                ],
                verification="Capture both directions continuously from before the SYN and check the client socket state.",
                next_action="Repeat the connection while capturing at the initiating endpoint.",
            )
        )
    elif "syn_observed" in states:
        findings.append(
            _finding(
                session_id,
                "SYN_WITHOUT_SYN_ACK",
                "A TCP SYN was observed without a matching SYN-ACK in the available capture.",
                support_ids,
                confidence=packet_confidence,
                severity=Severity.MEDIUM,
                alternatives=[
                    "The destination may be unavailable or have no listener.",
                    "A response may be delayed, lost, filtered, or outside the capture point.",
                ],
                verification="Check destination socket/listener state and capture both directions at the endpoint.",
                next_action="Repeat a controlled connection attempt and compare endpoint observations.",
                limitations=[
                    "This observation does not identify an upstream firewall, router, ISP, or NAT device as the cause."
                ],
            )
        )

    retransmissions = sum(item.retransmissions for item in sessions)
    if retransmissions:
        findings.append(
            _finding(
                session_id,
                "TCP_RETRANSMISSIONS_OBSERVED",
                f"The analyzer identified {retransmissions} retransmitted TCP payload segment(s).",
                support_ids,
                confidence=packet_confidence,
                severity=Severity.MEDIUM,
                alternatives=["Capture duplication or incomplete observation can affect retransmission classification."],
                verification="Compare sequence ranges and packet timestamps in the technical timeline.",
                next_action="Check packet loss and acknowledgments at both endpoints before assigning a cause.",
            )
        )

    heartbeat = next((item for item in evidence if item.evidence_type == "heartbeat_status"), None)
    if heartbeat and heartbeat.observation.get("status") == "overdue":
        findings.append(
            _finding(
                session_id,
                "HEARTBEAT_OVERDUE",
                "The configured heartbeat interval elapsed without an observed heartbeat.",
                [heartbeat.id],
                confidence=Confidence.POSSIBLE,
                severity=Severity.MEDIUM,
                alternatives=["The capture may have missed heartbeat payloads or the configured interval may not match the application."],
                verification="Confirm the heartbeat format, interval, and capture direction.",
                next_action="Compare application heartbeat logs with the packet timeline.",
            )
        )
    return findings
