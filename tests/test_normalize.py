from lolrmm_artifacts.normalize import canonical_os, expand_windows_path


def test_expand_appdata():
    assert expand_windows_path(r"%APPDATA%\AnyDesk\ad.trace") == r"C:\Users\*\AppData\Roaming\AnyDesk\ad.trace"


def test_expand_mixed_case():
    assert expand_windows_path(r"%appdata%\x") == r"C:\Users\*\AppData\Roaming\x"


def test_expand_programdata():
    assert expand_windows_path(r"%PROGRAMDATA%\AnyDesk\service.conf") == r"C:\ProgramData\AnyDesk\service.conf"


def test_unknown_env_var_preserved():
    assert expand_windows_path(r"%UNKNOWN%\foo") == r"%UNKNOWN%\foo"


def test_no_env_vars_noop():
    assert expand_windows_path(r"C:\Windows\Temp\foo.log") == r"C:\Windows\Temp\foo.log"


def test_canonical_os_variants():
    assert canonical_os("Windows") == "Windows"
    assert canonical_os("MacOS") == "MacOS"
    assert canonical_os("Mac") == "MacOS"
    assert canonical_os("MacOS 32bit") == "MacOS"
    assert canonical_os("  linux  ") == "Linux"
    assert canonical_os("IOS") == "iOS"
    assert canonical_os(None) is None
    assert canonical_os("") is None
