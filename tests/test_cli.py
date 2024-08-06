import unittest
from unittest.mock import patch
from src.cli import main

class TestCLI(unittest.TestCase):

    @patch("src.cli.scan_for_cve_2023_38831")
    @patch("src.cli.generate_report")
    def test_main(self, mock_generate_report, mock_scan):
        mock_scan.return_value = (True, "6.0.2")
        mock_generate_report.return_value = "Test Report"

        with patch("sys.argv", ["script_name", "--verbose"]):
            with self.assertLogs() as log:
                main()

        self.assertIn("Test Report", log.output[-1])

if __name__ == '__main__':
    unittest.main()
