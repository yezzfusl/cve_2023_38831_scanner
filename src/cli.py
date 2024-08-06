import argparse
from .scanner import scan_for_cve_2023_38831
from .report import generate_report

def parse_args():
    parser = argparse.ArgumentParser(description="Scan for CVE-2023-38831 vulnerability in WinRAR")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()

def main():
    args = parse_args()
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)

    is_vulnerable, version_or_error = scan_for_cve_2023_38831()
    report = generate_report(is_vulnerable, version_or_error)
    print(report)

if __name__ == "__main__":
    main()
