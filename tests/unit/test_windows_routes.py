import socket

import pytest

from netpath_sentinel.infrastructure import host as host_module
from netpath_sentinel.infrastructure.host import HostInspector
from netpath_sentinel.infrastructure.windows_routes import route_rows_to_models


def test_windows_route_rows_preserve_family_prefix_gateway_interface_and_metric() -> None:
    routes = route_rows_to_models(
        [
            {
                "family": socket.AF_INET,
                "destination": "0.0.0.0",
                "prefix_length": 0,
                "gateway": "192.0.2.1",
                "interface_index": 13,
                "metric": 35,
                "interface_metric": 7,
            },
            {
                "family": socket.AF_INET6,
                "destination": "2001:db8:1::9",
                "prefix_length": 64,
                "gateway": "::",
                "interface_index": 44,
                "metric": 20,
            },
        ],
        {13: "Wi-Fi", 44: "vEthernet (WSL)"},
    )

    assert {(route.destination, route.interface) for route in routes} == {
        ("0.0.0.0/0", "Wi-Fi"),
        ("2001:db8:1::/64", "vEthernet (WSL)"),
    }
    ipv4 = next(route for route in routes if route.destination == "0.0.0.0/0")
    ipv6 = next(route for route in routes if route.destination == "2001:db8:1::/64")
    assert ipv4.gateway == "192.0.2.1" and ipv4.metric == 42
    assert ipv6.gateway is None and ipv6.metric == 20
    assert (ipv4.address_family, ipv4.interface_index) == ("IPv4", 13)
    assert (ipv4.route_metric, ipv4.interface_metric) == (35, 7)
    assert (ipv6.address_family, ipv6.interface_index) == ("IPv6", 44)
    assert (ipv6.route_metric, ipv6.interface_metric) == (20, 0)


def test_windows_route_rows_keep_unmapped_interface_and_discard_malformed_rows() -> None:
    routes = route_rows_to_models(
        [
            {
                "family": socket.AF_INET,
                "destination": "192.0.2.7",
                "prefix_length": 24,
                "gateway": "0.0.0.0",
                "interface_index": 999,
                "metric": 0xFFFFFFFF,
            },
            {"family": socket.AF_INET, "destination": "not-an-ip"},
        ],
        {},
    )

    assert len(routes) == 1
    assert routes[0].destination == "192.0.2.0/24"
    assert routes[0].gateway is None
    assert routes[0].interface == "Interface index 999"
    assert routes[0].metric is None


def test_windows_vpn_and_hyperv_routes_keep_stable_interface_mapping() -> None:
    routes = route_rows_to_models(
        [
            {
                "family": socket.AF_INET,
                "destination": "10.40.0.0",
                "prefix_length": 16,
                "gateway": "10.40.0.1",
                "interface_index": 8,
                "metric": 5,
                "interface_metric": 10,
            },
            {
                "family": socket.AF_INET6,
                "destination": "fd00:1234::",
                "prefix_length": 64,
                "gateway": "::",
                "interface_index": 44,
                "metric": 20,
                "interface_metric": 30,
            },
        ],
        {8: "Fortinet VPN", 44: "vEthernet (Default Switch)"},
    )

    assert [(route.interface_index, route.interface) for route in routes] == [
        (8, "Fortinet VPN"),
        (44, "vEthernet (Default Switch)"),
    ]
    assert [route.metric for route in routes] == [15, 50]


def test_automatic_interface_uses_loopback_and_route_not_inventory_order() -> None:
    from netpath_sentinel.application.runner import DiagnosticRunner
    from netpath_sentinel.domain.models import InterfaceInfo, RouteInfo

    interfaces = [
        InterfaceInfo(name="vEthernet", is_up=True),
        InterfaceInfo(name="Wi-Fi", is_up=True),
        InterfaceInfo(name="Loopback Pseudo-Interface 1", is_up=True),
    ]
    routes = [RouteInfo(destination="0.0.0.0/0", interface="Wi-Fi", metric=35)]

    assert DiagnosticRunner._default_interface(interfaces, "127.0.0.1", routes) == (
        "Loopback Pseudo-Interface 1"
    )
    assert DiagnosticRunner._default_interface(interfaces, routes=routes) == "Wi-Fi"
    assert DiagnosticRunner._default_interface(interfaces) is None


def test_route_collection_failure_is_exposed_in_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        "netpath_sentinel.infrastructure.windows_routes.windows_routes",
        lambda: (_ for _ in ()).throw(OSError("GetIpForwardTable2 access denied")),
        raising=False,
    )
    monkeypatch.setattr(HostInspector, "interfaces", lambda self: [])
    monkeypatch.setattr(HostInspector, "listeners", lambda self: [])

    snapshot = HostInspector().snapshot()

    assert snapshot.routes == []
    assert snapshot.route_error is not None
    assert "GetIpForwardTable2 access denied" in snapshot.route_error


def test_linux_route_command_failure_is_not_reported_as_empty_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        host_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("ip command missing")),
    )

    with pytest.raises(RuntimeError, match="Linux route collection failed"):
        HostInspector().routes()
