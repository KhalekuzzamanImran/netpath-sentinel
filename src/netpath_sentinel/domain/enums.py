from enum import StrEnum


class DiagnosticMode(StrEnum):
    PASSIVE_CAPTURE = "passive_capture"
    ACTIVE_LISTENER = "active_listener"
    PCAP_REPLAY = "pcap_replay"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    INCONCLUSIVE = "inconclusive"


class EvidenceStatus(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    INCOMPLETE = "incomplete"
    NOT_COLLECTED = "not_collected"
    COLLECTION_FAILED = "collection_failed"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    INCONCLUSIVE = "inconclusive"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
