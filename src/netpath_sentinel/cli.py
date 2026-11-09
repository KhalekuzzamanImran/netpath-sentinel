import argparse
import json

from .infrastructure.host import HostInspector


def main() -> None:
    parser = argparse.ArgumentParser(prog="netpath-sentinel")
    parser.add_argument("command", choices=["inspect-host"], nargs="?", default="inspect-host")
    args = parser.parse_args()
    if args.command == "inspect-host":
        snapshot = HostInspector().snapshot()
        print(
            json.dumps(
                {
                    "hostname": snapshot.hostname,
                    "os": snapshot.os_version,
                    "interfaces": [i.model_dump() for i in snapshot.interfaces],
                    "routes": [r.model_dump() for r in snapshot.routes],
                    "route_error": snapshot.route_error,
                    "listeners": [listener.model_dump() for listener in snapshot.listeners],
                },
                indent=2,
            )
        )
