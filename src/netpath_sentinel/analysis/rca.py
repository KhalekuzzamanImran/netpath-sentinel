from netpath_sentinel.domain.enums import Confidence, Severity
from netpath_sentinel.domain.models import Evidence, Finding


def analyze(session_id: str, evidence: list[Evidence], tcp_handshakes: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    packet = next((e for e in evidence if e.evidence_type == "packet_summary"), None)
    ids = [e.id for e in evidence]
    if not packet:
        return [
            Finding(
                session_id=session_id,
                code="NO_PACKET_EVIDENCE",
                severity=Severity.MEDIUM,
                conclusion="TCP packet evidence was not collected; no network conclusion is supported.",
                confidence=Confidence.INCONCLUSIVE,
                supporting_evidence_ids=ids,
                recommended_verification="Run capture with a valid interface and sufficient privileges.",
                next_action="Verify capture backend and repeat the diagnostic window.",
            )
        ]
    observed = packet.observation.get("packets", 0)
    if not observed:
        if packet.status.value == "incomplete":
            findings.append(
                Finding(
                    session_id=session_id,
                    code="CAPTURE_INCOMPLETE_NO_PACKETS",
                    severity=Severity.INFO,
                    conclusion="No matching TCP packets were observed before the incomplete capture ended; no connection conclusion is supported.",
                    confidence=Confidence.INCONCLUSIVE,
                    supporting_evidence_ids=[packet.id],
                    alternatives=["The capture ended at a configured resource limit", "The capture was cancelled before traffic arrived"],
                    recommended_verification="Repeat with a larger packet limit or a complete capture window.",
                    next_action="Verify packet-limit and cancellation diagnostics before drawing a network conclusion.",
                )
            )
            return findings
        findings.append(
            Finding(
                session_id=session_id,
                code="NO_INCOMING_SYN",
                severity=Severity.MEDIUM,
                conclusion="No matching TCP packets were observed during the capture window.",
                confidence=Confidence.INCONCLUSIVE,
                supporting_evidence_ids=[packet.id],
                alternatives=[
                    "The source did not attempt a connection",
                    "Wrong destination or interface",
                    "The capture point, filter, or capture engine may have missed the attempt",
                ],
                recommended_verification="Confirm the source configuration and capture on the actual egress interface.",
                next_action="Repeat while triggering a controlled connection attempt.",
            )
        )
    elif "complete" in tcp_handshakes:
        findings.append(
            Finding(
                session_id=session_id,
                code="TCP_HANDSHAKE_COMPLETE",
                severity=Severity.INFO,
                conclusion="A complete TCP three-way handshake was observed.",
                confidence=Confidence.CONFIRMED,
                supporting_evidence_ids=[packet.id],
                recommended_verification="Correlate payload timing with the source application.",
                next_action="Inspect payload and heartbeat freshness.",
            )
        )
    elif "syn_observed" in tcp_handshakes:
        findings.append(
            Finding(
                session_id=session_id,
                code="SYN_WITHOUT_SYN_ACK",
                severity=Severity.MEDIUM,
                conclusion="A SYN was observed without a matching SYN-ACK in the available capture.",
                confidence=Confidence.POSSIBLE,
                supporting_evidence_ids=[packet.id],
                alternatives=["The response was lost, filtered, delayed, or outside the capture point"],
                recommended_verification="Capture both directions at the endpoint and verify the listener state.",
                next_action="Repeat a controlled connection attempt and compare endpoint socket state.",
            )
        )
    return findings
