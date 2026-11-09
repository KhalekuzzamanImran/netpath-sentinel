"""Read-only IPv4/IPv6 route discovery through the Windows IP Helper API."""

from __future__ import annotations

import ctypes
import ipaddress
import socket
from collections.abc import Iterable, Mapping

from netpath_sentinel.domain.models import RouteInfo


def _as_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise ValueError("route field is not an integer")


class _SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("port", ctypes.c_ushort),
        ("address", ctypes.c_ubyte * 4),
        ("zero", ctypes.c_ubyte * 8),
    ]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("port", ctypes.c_ushort),
        ("flow_info", ctypes.c_uint32),
        ("address", ctypes.c_ubyte * 16),
        ("scope_id", ctypes.c_uint32),
    ]


class _SockaddrInet(ctypes.Union):
    _fields_ = [("ipv4", _SockaddrIn), ("ipv6", _SockaddrIn6)]


class _IpAddressPrefix(ctypes.Structure):
    _fields_ = [("prefix", _SockaddrInet), ("prefix_length", ctypes.c_ubyte)]


class _MibIpForwardRow2(ctypes.Structure):
    _fields_ = [
        ("interface_luid", ctypes.c_uint64),
        ("interface_index", ctypes.c_uint32),
        ("destination_prefix", _IpAddressPrefix),
        ("next_hop", _SockaddrInet),
        ("site_prefix_length", ctypes.c_ubyte),
        ("valid_lifetime", ctypes.c_uint32),
        ("preferred_lifetime", ctypes.c_uint32),
        ("metric", ctypes.c_uint32),
        ("protocol", ctypes.c_uint32),
        ("loopback", ctypes.c_ubyte),
        ("autoconfigure_address", ctypes.c_ubyte),
        ("publish", ctypes.c_ubyte),
        ("immortal", ctypes.c_ubyte),
        ("age", ctypes.c_uint32),
        ("origin", ctypes.c_uint32),
    ]


class _MibIpForwardTable2(ctypes.Structure):
    _fields_ = [
        ("num_entries", ctypes.c_uint32),
        ("table", _MibIpForwardRow2 * 1),
    ]


def route_rows_to_models(
    rows: Iterable[Mapping[str, object]], interface_names: Mapping[int, str]
) -> list[RouteInfo]:
    """Normalize API-shaped rows, retaining all adapters and both IP families."""
    result: list[RouteInfo] = []
    for row in rows:
        try:
            family = _as_int(row["family"])
            address = str(row["destination"])
            prefix_length = _as_int(row["prefix_length"])
            destination = str(
                ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)
            )
            gateway = str(row["gateway"])
            if ipaddress.ip_address(gateway).is_unspecified:
                gateway = ""
            interface_index = _as_int(row["interface_index"])
            metric = _as_int(row["metric"])
            interface_metric = _as_int(row.get("interface_metric", 0))
        except (KeyError, TypeError, ValueError):
            continue
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        result.append(
            RouteInfo(
                destination=destination,
                gateway=gateway or None,
                interface=interface_names.get(
                    interface_index, f"Interface index {interface_index}"
                ),
                interface_index=interface_index,
                address_family="IPv4" if family == socket.AF_INET else "IPv6",
                route_metric=metric if metric != 0xFFFFFFFF else None,
                interface_metric=interface_metric,
                metric=(metric + interface_metric) if metric != 0xFFFFFFFF else None,
            )
        )
    return sorted(result, key=lambda route: (route.destination, route.interface or ""))


def _address(sockaddr: _SockaddrInet) -> tuple[int, str] | None:
    family = int(sockaddr.ipv4.family)
    if family == socket.AF_INET:
        return family, socket.inet_ntop(family, bytes(sockaddr.ipv4.address))
    family = int(sockaddr.ipv6.family)
    if family == socket.AF_INET6:
        return family, socket.inet_ntop(family, bytes(sockaddr.ipv6.address))
    return None


def _interface_data() -> tuple[dict[int, str], dict[tuple[int, int], int]]:
    try:
        from scapy.arch.windows import get_windows_if_list

        adapters = [
            adapter
            for adapter in get_windows_if_list()
            if adapter.get("index") is not None and adapter.get("name")
        ]
        names = {int(adapter["index"]): str(adapter["name"]) for adapter in adapters}
        metrics = {
            (int(adapter["index"]), int(family)): int(adapter.get(metric_key, 0))
            for adapter in adapters
            for family, metric_key in (
                (socket.AF_INET, "ipv4_metric"),
                (socket.AF_INET6, "ipv6_metric"),
            )
            if adapter.get(metric_key) is not None
        }
        return names, metrics
    except (ImportError, OSError, KeyError, TypeError, ValueError):
        try:
            return {int(index): name for index, name in socket.if_nameindex()}, {}
        except OSError as exc:
            raise OSError(f"could not map Windows route interface indexes: {exc}") from exc


def windows_routes() -> list[RouteInfo]:
    """Return the Windows IPv4/IPv6 forwarding table without changing it."""
    if hasattr(ctypes, "WinDLL"):
        ip_helper = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    else:
        raise OSError("Windows IP Helper APIs are only available on Windows")

    get_table = ip_helper.GetIpForwardTable2
    get_table.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.POINTER(_MibIpForwardTable2))]
    get_table.restype = ctypes.c_uint32
    free_table = ip_helper.FreeMibTable
    free_table.argtypes = [ctypes.c_void_p]
    free_table.restype = None

    table_pointer = ctypes.POINTER(_MibIpForwardTable2)()
    status = int(get_table(0, ctypes.byref(table_pointer)))  # AF_UNSPEC: IPv4 and IPv6.
    if status:
        raise OSError(status, "GetIpForwardTable2 failed")
    if not table_pointer:
        return []

    try:
        table = table_pointer.contents
        row_address = ctypes.addressof(table) + _MibIpForwardTable2.table.offset
        rows = ctypes.cast(row_address, ctypes.POINTER(_MibIpForwardRow2))
        interface_names, interface_metrics = _interface_data()
        normalized_rows: list[dict[str, object]] = []
        for index in range(table.num_entries):
            row = rows[index]
            prefix_address = _address(row.destination_prefix.prefix)
            next_hop = _address(row.next_hop)
            if prefix_address is None or next_hop is None:
                continue
            normalized_rows.append(
                {
                    "family": prefix_address[0],
                    "destination": prefix_address[1],
                    "prefix_length": int(row.destination_prefix.prefix_length),
                    "gateway": next_hop[1],
                    "interface_index": int(row.interface_index),
                    "metric": int(row.metric),
                    "interface_metric": interface_metrics.get(
                        (int(row.interface_index), prefix_address[0]), 0
                    ),
                }
            )
        return route_rows_to_models(normalized_rows, interface_names)
    finally:
        free_table(table_pointer)
