import os
import winreg
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import get_winrar_path
from .report import generate_report
from .integrity import check_file_integrity
from .memory_scanner import scan_process_memory
from .network_analyzer import analyze_network_traffic
from .sandbox import Sandbox
from .database import Database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def scan_for_cve_2023_38831():
    winrar_path = get_winrar_path()
    if not winrar_path:
        logger.warning("WinRAR not found on the system.")
        return False, "WinRAR not found on the system."

    vulnerable_version = False
    version = ""

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinRAR\Version") as key:
            version = winreg.QueryValueEx(key, "Version")[0]

        major, minor, build = map(int, version.split('.'))
        if major < 6 or (major == 6 and minor == 0 and build <= 2):
            vulnerable_version = True
    except WindowsError:
        logger.error("Unable to determine WinRAR version.")
        return False, "Unable to determine WinRAR version."

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        futures.append(executor.submit(check_file_integrity, winrar_path))
        futures.append(executor.submit(scan_process_memory, "WinRAR.exe"))
        futures.append(executor.submit(analyze_network_traffic, "eth0", duration=30))

        for future in as_completed(futures):
            result = future.result()
            if isinstance(result, tuple):
                operation, status = result
                if operation == "integrity" and not status:
                    logger.warning(f"File integrity check failed for {winrar_path}")
                    vulnerable_version = True
                elif operation == "memory" and status:
                    logger.warning("Suspicious patterns found in WinRAR process memory")
                    vulnerable_version = True
                elif operation == "network" and status:
                    logger.warning("Suspicious network traffic detected")
                    vulnerable_version = True

    with Sandbox() as sandbox:
        sandbox_winrar_path = sandbox.copy_file_to_sandbox(winrar_path)
        if sandbox_winrar_path:
            returncode, stdout, stderr = sandbox.run_command([sandbox_winrar_path, "--version"])
            if returncode != 0:
                logger.warning(f"Unexpected behavior in sandbox: {stderr}")
                vulnerable_version = True

    db = Database()
    db.insert_scan_result(
        vulnerable_version,
        version,
        "Integrity check passed" if not vulnerable_version else "Integrity check failed",
        "No suspicious patterns in memory" if not vulnerable_version else "Suspicious patterns in memory",
        "No suspicious network traffic" if not vulnerable_version else "Suspicious network traffic detected",
        "No issues in sandbox environment" if not vulnerable_version else "Issues detected in sandbox environment"
    )

    logger.info(f"Scan completed. WinRAR version: {version}, Vulnerable: {vulnerable_version}")
    return vulnerable_version, version

def main():
    is_vulnerable, version_or_error = scan_for_cve_2023_38831()
    report = generate_report(is_vulnerable, version_or_error)
    print(report)

if __name__ == "__main__":
    main()
