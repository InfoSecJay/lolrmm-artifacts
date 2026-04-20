"""Path / OS normalization helpers.

Goals:
- Expand Windows env-var paths like `%APPDATA%\\AnyDesk\\ad.trace` into a
  wildcarded user-relative form `C:\\Users\\*\\AppData\\Roaming\\AnyDesk\\ad.trace`
  that's easier to feed into SIEM/EDR file-path searches.
- Map the messy OS label set ("MacOS 32bit", "Mac", "MACOS") into a small
  canonical vocabulary: Windows / Linux / MacOS / Android / iOS / ChromeOS.
- Keep the raw value alongside the expanded one so consumers can pick.
"""

from __future__ import annotations

import re

# case-insensitive %VAR% expansion map — values use Windows separators and a
# `*` wildcard for per-user directories so SIEM queries can LIKE against them.
_WIN_ENV_EXPANSIONS: dict[str, str] = {
    "APPDATA": r"C:\Users\*\AppData\Roaming",
    "LOCALAPPDATA": r"C:\Users\*\AppData\Local",
    "PROGRAMDATA": r"C:\ProgramData",
    "PROGRAMFILES": r"C:\Program Files",
    "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
    "SYSTEMROOT": r"C:\Windows",
    "WINDIR": r"C:\Windows",
    "TEMP": r"C:\Users\*\AppData\Local\Temp",
    "TMP": r"C:\Users\*\AppData\Local\Temp",
    "USERPROFILE": r"C:\Users\*",
    "PUBLIC": r"C:\Users\Public",
    "ALLUSERSPROFILE": r"C:\ProgramData",
    "COMMONPROGRAMFILES": r"C:\Program Files\Common Files",
    "COMMONPROGRAMFILES(X86)": r"C:\Program Files (x86)\Common Files",
    "HOMEDRIVE": r"C:",
    "HOMEPATH": r"\Users\*",
    "SYSTEMDRIVE": r"C:",
}

_ENV_RE = re.compile(r"%([A-Za-z0-9_()]+)%")


def expand_windows_path(path: str) -> str:
    """Replace %ENV% tokens with canonical wildcarded paths. Case-insensitive."""

    def repl(m: re.Match[str]) -> str:
        key = m.group(1).upper()
        return _WIN_ENV_EXPANSIONS.get(key, m.group(0))

    return _ENV_RE.sub(repl, path)


_OS_MAP = {
    "windows": "Windows",
    "win": "Windows",
    "linux": "Linux",
    "mac": "MacOS",
    "macos": "MacOS",
    "osx": "MacOS",
    "mac os": "MacOS",
    "darwin": "MacOS",
    "android": "Android",
    "ios": "iOS",
    "chromeos": "ChromeOS",
    "chrome os": "ChromeOS",
}


def canonical_os(value: str | None) -> str | None:
    """Map a raw OS label to the canonical set or return None if unrecognised."""
    if not value:
        return None
    lower = value.strip().lower()
    # strip common qualifiers so "MacOS 32bit" / "Windows 10" collapse correctly
    lower = re.sub(r"\b(32|64)\s*bit\b", "", lower).strip()
    lower = re.sub(r"\s+", " ", lower)
    if lower in _OS_MAP:
        return _OS_MAP[lower]
    for k, v in _OS_MAP.items():
        if lower.startswith(k):
            return v
    return value.strip() or None


def clean_str(value: str | None) -> str | None:
    """Strip whitespace and collapse empties to None."""
    if value is None:
        return None
    s = value.strip()
    return s or None
