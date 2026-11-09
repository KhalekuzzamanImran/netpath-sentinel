"""Create a CycloneDX inventory from uv.lock and the installed lock environment."""

from __future__ import annotations

import json
import re
import sys
import tomllib
from importlib.metadata import PackageNotFoundError, metadata
from pathlib import Path
from urllib.parse import quote


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    lock_path = Path(sys.argv[1] if len(sys.argv) > 1 else "uv.lock")
    output_path = Path(sys.argv[2] if len(sys.argv) > 2 else "dist/sbom.cdx.json")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock["package"]
    components: list[dict[str, object]] = []
    dependencies: list[dict[str, object]] = []
    for package in sorted(packages, key=lambda item: item["name"].lower()):
        name = package["name"]
        version = package["version"]
        ref = f"pkg:pypi/{quote(normalized(name), safe='-')}@{version}"
        source = f"https://pypi.org/project/{quote(name, safe='-')}/{version}/"
        project_urls = []
        try:
            package_metadata = metadata(name)
        except PackageNotFoundError:
            package_metadata = None
        if package_metadata:
            project_urls = package_metadata.get_all("Project-URL", [])
        source_url = next(
            (line.split(", ", 1)[1] for line in project_urls if line.lower().startswith(("source, ", "repository, "))),
            source,
        )
        component: dict[str, object] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": ref,
            "bom-ref": ref,
            "externalReferences": [
                {"type": "distribution", "url": source},
                {"type": "vcs", "url": source_url},
            ],
        }
        if package_metadata:
            license_value = package_metadata.get("License-Expression") or package_metadata.get("License")
            if license_value and license_value.strip() not in {"UNKNOWN", "Unknown"}:
                component["licenses"] = [{"license": {"name": license_value.strip()}}]
            urls = [line.split(", ", 1)[1] for line in project_urls if ", " in line]
            if urls:
                external_references = component["externalReferences"]
                assert isinstance(external_references, list)
                external_references.append({"type": "website", "url": urls[0]})
        components.append(component)
        child_refs = []
        for dependency in package.get("dependencies", []):
            child = next(
                (candidate for candidate in packages if normalized(candidate["name"]) == normalized(dependency["name"])),
                None,
            )
            if child:
                child_refs.append(
                    f"pkg:pypi/{quote(normalized(child['name']), safe='-')}@{child['version']}"
                )
        dependencies.append({"ref": ref, "dependsOn": sorted(set(child_refs))})

    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "netpath-sentinel",
                "version": "0.1.0",
                "licenses": [{"license": {"name": "MIT"}}],
            }
        },
        "components": components,
        "dependencies": dependencies,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {output_path} ({len(components)} locked packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
