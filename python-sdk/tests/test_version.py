"""Verify that version strings are consistent across the Python SDK (#85).

The SDK version appears in three places:
  - pyproject.toml          (single source of truth for packaging)
  - xproof/__init__.py      (fallback string when not installed)
  - xproof/client.py        (fallback string for User-Agent header)

This test reads all three and asserts they are identical so a release cannot
accidentally ship with mismatched version numbers.
"""

import re
from pathlib import Path

SDK_ROOT = Path(__file__).parent.parent


def _read_pyproject_version() -> str:
    text = (SDK_ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "version field not found in pyproject.toml"
    return match.group(1)


def _read_fallback_version(filepath: Path) -> str:
    text = filepath.read_text()
    match = re.search(r'__version__\s*=\s*"([^"]+)".*fallback', text)
    assert match, f"fallback __version__ string not found in {filepath}"
    return match.group(1)


def test_version_consistent_across_sdk_files() -> None:
    """pyproject.toml, __init__.py, and client.py fallbacks must all agree."""
    pyproject_ver = _read_pyproject_version()
    init_ver = _read_fallback_version(SDK_ROOT / "xproof" / "__init__.py")
    client_ver = _read_fallback_version(SDK_ROOT / "xproof" / "client.py")

    assert pyproject_ver == init_ver, (
        f"Version mismatch: pyproject.toml={pyproject_ver!r}, "
        f"xproof/__init__.py fallback={init_ver!r}"
    )
    assert pyproject_ver == client_ver, (
        f"Version mismatch: pyproject.toml={pyproject_ver!r}, "
        f"xproof/client.py fallback={client_ver!r}"
    )
