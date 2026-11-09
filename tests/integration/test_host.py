from netpath_sentinel.infrastructure.host import HostInspector


def test_host_snapshot_is_read_only_and_structured() -> None:
    snapshot = HostInspector().snapshot()
    assert snapshot.hostname
    assert isinstance(snapshot.interfaces, list)
    assert isinstance(snapshot.routes, list)
