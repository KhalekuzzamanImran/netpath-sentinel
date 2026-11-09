import platform
import socket
import subprocess
from dataclasses import dataclass

import psutil

from netpath_sentinel.domain.models import InterfaceInfo, ListenerInfo, RouteInfo


@dataclass(frozen=True)
class HostSnapshot:
    hostname: str
    os_name: str
    os_version: str
    interfaces: list[InterfaceInfo]
    routes: list[RouteInfo]
    route_error: str | None
    listeners: list[ListenerInfo]


class HostInspector:
    """Read-only host inspection using psutil and native structured utilities."""

    def snapshot(self) -> HostSnapshot:
        route_error = None
        try:
            routes = self.routes()
        except (OSError, RuntimeError, NotImplementedError) as exc:
            routes = []
            route_error = f"{platform.system()} route discovery failed: {exc}"
        return HostSnapshot(
            hostname=socket.gethostname(),
            os_name=platform.system(),
            os_version=platform.platform(),
            interfaces=self.interfaces(),
            routes=routes,
            route_error=route_error,
            listeners=self.listeners(),
        )

    def interfaces(self) -> list[InterfaceInfo]:
        try:
            addresses_by_name = psutil.net_if_addrs()
            stats_by_name = psutil.net_if_stats()
            counters = psutil.net_io_counters(pernic=True)
        except (OSError, PermissionError):
            return []
        result: list[InterfaceInfo] = []
        for name, addrs in addresses_by_name.items():
            addresses = [address.address for address in addrs if address.address]
            mac = next((a.address for a in addrs if a.family == psutil.AF_LINK), None)
            stats = counters.get(name)
            result.append(
                InterfaceInfo(
                    name=name,
                    is_up=stats_by_name.get(name).isup if name in stats_by_name else False,
                    mtu=stats_by_name.get(name).mtu if name in stats_by_name else None,
                    mac=mac,
                    addresses=addresses,
                    rx_bytes=stats.bytes_recv if stats else None,
                    tx_bytes=stats.bytes_sent if stats else None,
                )
            )
        return result

    def routes(self) -> list[RouteInfo]:
        if platform.system() == "Windows":
            from netpath_sentinel.infrastructure.windows_routes import windows_routes

            return windows_routes()
        if platform.system() == "Linux":
            try:
                completed = subprocess.run(
                    ["ip", "-j", "route"], check=True, capture_output=True, text=True
                )
                import json

                entries = json.loads(completed.stdout)
                return [
                    RouteInfo(
                        destination=e.get("dst", "default"),
                        gateway=e.get("gateway"),
                        interface=e.get("dev"),
                        source=e.get("prefsrc"),
                        metric=e.get("metric"),
                    )
                    for e in entries
                ]
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                raise RuntimeError(f"Linux route collection failed: {exc}") from exc
        raise NotImplementedError(
            f"route collection is not implemented on {platform.system()}"
        )

    def listeners(self) -> list[ListenerInfo]:
        result: list[ListenerInfo] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != psutil.CONN_LISTEN or not conn.laddr:
                    continue
                process = None
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid).name()
                    except psutil.Error:
                        process = None
                result.append(
                    ListenerInfo(
                        protocol="tcp",
                        local_address=conn.laddr.ip,
                        local_port=conn.laddr.port,
                        pid=conn.pid,
                        process=process,
                        state=conn.status,
                    )
                )
        except psutil.AccessDenied:
            pass
        return result

    def route_for(self, destination: str) -> RouteInfo:
        """Use the kernel's route selection without sending traffic."""
        if platform.system() == "Linux":
            try:
                completed = subprocess.run(
                    ["ip", "-j", "route", "get", destination],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                import json

                item = json.loads(completed.stdout)[0]
                return RouteInfo(
                    destination=destination,
                    gateway=item.get("gateway"),
                    interface=item.get("dev"),
                    source=item.get("prefsrc"),
                )
            except (OSError, subprocess.SubprocessError, ValueError) as exc:
                raise RuntimeError(f"route lookup failed: {exc}") from exc
        raise NotImplementedError(f"route selection is not implemented on {platform.system()}")
