from datetime import datetime


def evaluate_heartbeat(
    last_seen: datetime | None,
    last_heartbeat: datetime | None,
    now: datetime,
    expected_interval: float | None,
    timeout: float | None,
    mode: str,
) -> dict[str, object]:
    if mode == "disabled":
        return {"status": "not_configured", "missed": 0}
    if last_heartbeat is None:
        return {"status": "missing", "missed": 1}
    threshold = timeout or expected_interval or 0
    age = (now - last_heartbeat).total_seconds()
    return {
        "status": "overdue" if age > threshold else "healthy",
        "age_seconds": age,
        "missed": int(age // threshold) if threshold else 0,
        "last_seen": last_seen is not None,
    }
