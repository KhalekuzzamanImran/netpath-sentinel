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
                    "Upstream routing, NAT, firewall, or capture loss",
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
    return findings
