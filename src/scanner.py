import os
import winreg
import logging
from .utils import get_winrar_path
from .report import generate_report
from .integrity import check_file_integrity

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def scan_for_cve_2023_38831():
    winrar_path = get_winrar_path()
    if not winrar_path:
        logging.warning("WinRAR not found on the system.")
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
        logging.error("Unable to determine WinRAR version.")
        return False, "Unable to determine WinRAR version."

    # Check file integrity
    integrity_status = check_file_integrity(winrar_path)
    if not integrity_status:
        logging.warning(f"File integrity check failed for {winrar_path}")
        return vulnerable_version, f"{version} (Integrity check failed)"

    logging.info(f"Scan completed. WinRAR version: {version}, Vulnerable: {vulnerable_version}")
    return vulnerable_version, version

def main():
    is_vulnerable, version_or_error = scan_for_cve_2023_38831()
    report = generate_report(is_vulnerable, version_or_error)
    print(report)

if __name__ == "__main__":
    main()
