import sys
from ipaddress import ip_network

import pytest

from netpath_sentinel.infrastructure.host import HostInspector


@pytest.mark.skipif(sys.platform != "win32", reason="Windows IP Helper API test")
def test_windows_route_discovery_returns_default_ipv4_and_ipv6_routes() -> None:
    snapshot = HostInspector().snapshot()

    assert snapshot.route_error is None
    assert snapshot.routes
    assert any(route.destination == "0.0.0.0/0" for route in snapshot.routes)
    assert any(ip_network(route.destination).version == 6 for route in snapshot.routes)
    default_v4 = next(route for route in snapshot.routes if route.destination == "0.0.0.0/0")
    assert default_v4.interface
    assert default_v4.metric is not None
