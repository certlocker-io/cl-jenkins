#!/usr/bin/env python3
"""Set the Maven plugin version from a matching, validated release tag."""

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def prepare_release(tag: str, pom: Path) -> str:
    number = r"(?:0|[1-9][0-9]*)"
    match = re.fullmatch(rf"v(({number}\.{number}\.{number})(?:-rc\.{number})?)", tag)
    if not match:
        raise ValueError("Use a release tag such as v0.2.0 or v0.2.0-rc.1")
    version, base = match.groups()
    source = pom.read_text(encoding="utf-8")
    project = ET.fromstring(source)
    current = project.findtext("{http://maven.apache.org/POM/4.0.0}version")
    if current not in {version, version + "-SNAPSHOT", base + "-SNAPSHOT"}:
        raise ValueError(f"Release {version} does not match the POM version {current}")
    updated, count = re.subn(
        rf"(<version>\s*){re.escape(current)}(\s*</version>)",
        lambda m: m[1] + version + m[2],
        source,
    )
    if count != 1:
        raise ValueError("Expected exactly one matching project version; POM left unchanged")
    pom.write_text(updated, encoding="utf-8")
    return version


if __name__ == "__main__":
    try:
        print("Prepared release version:", prepare_release(sys.argv[1], Path("pom.xml")))
    except (IndexError, ValueError) as error:
        raise SystemExit(str(error)) from error
