from netpath_sentinel.analysis.rca import analyze
from netpath_sentinel.domain.enums import EvidenceStatus
from netpath_sentinel.domain.models import Evidence


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
    assert findings[0].code == "NO_INCOMING_SYN"
    assert findings[0].confidence.value == "inconclusive"
