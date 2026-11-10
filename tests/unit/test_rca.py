from netpath_sentinel.analysis.rca import analyze
from netpath_sentinel.domain.enums import EvidenceStatus
from netpath_sentinel.domain.models import Evidence, TCPSession


def test_no_packets_is_inconclusive() -> None:
    evidence = [
        Evidence(
            session_id="s1",
            evidence_type="packet_summary",
            source="replay",
            status=EvidenceStatus.OBSERVED,
            observation={"packets": 0},
        )
    ]
    findings = analyze("s1", evidence, [])
    assert findings[0].code == "NO_PACKETS_OBSERVED"
    assert findings[0].confidence.value == "inconclusive"


def test_incomplete_capture_without_packets_does_not_claim_no_attempt() -> None:
    evidence = Evidence(
        session_id="s1",
        evidence_type="packet_summary",
        source="pcap",
        status=EvidenceStatus.INCOMPLETE,
        observation={"packets": 0, "capture_complete": False},
    )
    findings = analyze("s1", [evidence], [])
    assert findings[0].code == "CAPTURE_INCOMPLETE_NO_PACKETS"
    assert findings[0].confidence.value == "inconclusive"
    assert evidence.id in findings[0].supporting_evidence_ids


def test_complete_handshake_without_payload_is_reported_conservatively() -> None:
    packet_summary = Evidence(
        session_id="s1",
        evidence_type="packet_summary",
        source="loopback",
        status=EvidenceStatus.OBSERVED,
        observation={"packets": 3, "capture_complete": True},
    )
    session = TCPSession(
        client_ip="192.0.2.10",
        client_port=41000,
        server_ip="192.0.2.20",
        server_port=6000,
        handshake="complete",
    )

    findings = analyze("s1", [packet_summary], ["complete"], [session])

    assert {item.code for item in findings} == {
        "TCP_HANDSHAKE_COMPLETE",
        "HANDSHAKE_WITHOUT_PAYLOAD",
    }
    assert all(packet_summary.id in item.supporting_evidence_ids for item in findings)
    assert all(item.alternatives and item.limitations and item.next_action for item in findings)


def test_midstream_capture_is_not_classified_as_handshake_failure() -> None:
    packet_summary = Evidence(
        session_id="s1",
        evidence_type="packet_summary",
        source="pcap",
        status=EvidenceStatus.OBSERVED,
        observation={"packets": 2, "capture_complete": True},
    )
    session = TCPSession(
        client_ip="192.0.2.10",
        client_port=41000,
        server_ip="192.0.2.20",
        server_port=6000,
        capture_started_midstream=True,
        handshake="not_observed_midstream",
    )

    findings = analyze("s1", [packet_summary], [session.handshake], [session])

    assert [item.code for item in findings] == ["MIDSTREAM_CAPTURE"]
    assert findings[0].confidence.value == "inconclusive"


def test_capture_permission_error_creates_actionable_inconclusive_finding() -> None:
    capture_error = Evidence(
        session_id="s1",
        evidence_type="capture_error",
        source="capture_backend",
        status=EvidenceStatus.PERMISSION_DENIED,
        observation={"error_category": "permission_denied", "error": "access denied"},
    )

    findings = analyze("s1", [capture_error], [])

    assert findings[0].code == "CAPTURE_PERMISSION_DENIED"
    assert findings[0].confidence.value == "inconclusive"
    assert capture_error.id in findings[0].supporting_evidence_ids
