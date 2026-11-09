# Licensing and redistribution review

This is a preliminary dependency and build-tool inventory for release planning,
not a substitute for reviewing the exact locked wheel contents and obligations
before publishing each platform artifact.

| Component | License information | Release action |
| --- | --- | --- |
| NetPath Sentinel source and original SVG icon | MIT, per project metadata | Include the project MIT license in source and binary distributions. |
| Scapy 2.8.x | GPL-2.0-only; Scapy states code, tests, and tools are GPL v2 | Scapy is imported by capture/replay code and is included by PyInstaller. Obtain a distribution-compatibility review for each intended product model. A closed-source commercial release is blocked until this is resolved through GPL compliance, architectural separation/replacement, or permission from the rights holders. Include GPL-2.0 text and corresponding-source obligations if distributing under GPL. |
| PySide6 / Qt for Python community distribution | LGPLv3/GPLv3 options; Qt also offers commercial terms | Inventory the exact included Qt modules and notices. For LGPL use, preserve replaceability/relinking rights and provide required license texts and modifications/source notices. Use an appropriate Qt commercial license if the product cannot meet those obligations. |
| PyInstaller | GPL-2.0 with an exception permitting bundled applications; a few files are Apache-2.0 | Keep PyInstaller's exception and the bundled dependency licenses in the release review. |
| Pydantic, psutil, SQLAlchemy, Alembic, pytest, Ruff, mypy, and other locked dependencies | Check the exact versions and wheel metadata in `uv.lock`; several direct dependencies use permissive licenses | Generate and retain a versioned SBOM and third-party notices from the locked environment for every release build. Review transitive dependencies, Qt plugins, and platform binaries too. |
| Inno Setup | Inno Setup authors request a commercial license when used commercially, including CI compilation | Obtain the applicable license before commercial release builds. |
| Npcap | Separately licensed; redistribution requires appropriate Npcap OEM terms or permission | Do not bundle the installer or runtime. Direct users to Npcap's official download and licensing terms. |

Official references:

- [Qt for Python licensing](https://doc.qt.io/qtforpython-6/) and [Qt 6.12 licensing options](https://doc.qt.io/qt-6/licensing.html)
- [Qt commercial use](https://doc.qt.io/qtforpython-6.10/commercial/index.html)
- [Scapy license](https://github.com/secdev/scapy)
- [PyInstaller license and exception](https://www.pyinstaller.org/en/stable/license.html)
- [Inno Setup commercial licensing](https://jrsoftware.org/isorder.php) and [purchase terms](https://jrsoftware.org/ishelp/topic_purchase.htm)
- [Npcap license](https://npcap.com/license) and [OEM redistribution requirements](https://npcap.com/oem/redist)

Phase 8 confirmed Npcap 1.90 was installed on the Windows acceptance host; the
Phase 8 PyInstaller archive inspection found no `wpcap.dll`, `Packet.dll`, or
`npcap.sys` embedded in the application executable. The Linux one-file builds
package Scapy along with the Qt runtime, so Linux packaging does not avoid
these licensing obligations. Do not describe the application distribution as
MIT-only.

## Release checklist

- [ ] Legal review approves Scapy GPL-2.0-only distribution model and source/
  corresponding-source obligations for each artifact.
- [ ] Qt modules, plugins, notices, modifications, and LGPL replaceability or
  commercial license obligations are reviewed per platform.
- [ ] Generated `dist/sbom.cdx.json` is reviewed against the locked wheels and
  actual PyInstaller/Qt contents; missing metadata is investigated.
- [ ] Third-party license texts/notices are included in artifacts as required.
- [ ] Npcap remains a separately licensed optional install unless OEM
  redistribution rights are obtained in writing.
- [ ] Inno Setup commercial build license is confirmed before commercial EXE
  builds.
- [ ] Icon/asset provenance and license are confirmed; retain the original SVG
  and Windows ICO attribution/source records.
- [ ] Release approver reviews checksums, build provenance, platform evidence,
  and artifact contents before signing or publication.

The generated SBOM obtains license identifiers from installed package metadata
and associates packages with the `uv.lock` dependency graph. Metadata can be
missing, ambiguous, or inaccurate and is not a legal determination.
