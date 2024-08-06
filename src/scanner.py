import os
import winreg
from .utils import get_winrar_path
from .report import generate_report

def scan_for_cve_2023_38831():
    winrar_path = get_winrar_path()
    if not winrar_path:
        return False, "WinRAR not found on the system."

    vulnerable_version = False
    version = ""

    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinRAR\Version")
        version = winreg.QueryValueEx(key, "Version")[0]
        winreg.CloseKey(key)

        major, minor, build = map(int, version.split('.'))
        if major < 6 or (major == 6 and minor == 0 and build <= 2):
            vulnerable_version = True
    except WindowsError:
        return False, "Unable to determine WinRAR version."

    return vulnerable_version, version

def main():
    is_vulnerable, version_or_error = scan_for_cve_2023_38831()
    report = generate_report(is_vulnerable, version_or_error)
    print(report)

if __name__ == "__main__":
    main()
