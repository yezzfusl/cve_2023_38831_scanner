def generate_report(is_vulnerable, version_or_error):
    if isinstance(version_or_error, str):
        return f"Scan result: {version_or_error}"
    
    if is_vulnerable:
        return f"System is VULNERABLE to CVE-2023-38831. WinRAR version: {version_or_error}"
    else:
        return f"System is NOT vulnerable to CVE-2023-38831. WinRAR version: {version_or_error}"
