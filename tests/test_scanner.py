import unittest
from unittest.mock import patch
from src.scanner import scan_for_cve_2023_38831

class TestScanner(unittest.TestCase):

    @patch('src.utils.get_winrar_path')
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_vulnerable_version(self, mock_query, mock_open, mock_get_path):
        mock_get_path.return_value = "C:\\Program Files\\WinRAR\\WinRAR.exe"
        mock_open.return_value = "mocked_key"
        mock_query.return_value = ("6.0.2", 1)

        is_vulnerable, version = scan_for_cve_2023_38831()
        self.assertTrue(is_vulnerable)
        self.assertEqual(version, "6.0.2")

    @patch('src.utils.get_winrar_path')
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_non_vulnerable_version(self, mock_query, mock_open, mock_get_path):
        mock_get_path.return_value = "C:\\Program Files\\WinRAR\\WinRAR.exe"
        mock_open.return_value = "mocked_key"
        mock_query.return_value = ("6.1.0", 1)

        is_vulnerable, version = scan_for_cve_2023_38831()
        self.assertFalse(is_vulnerable)
        self.assertEqual(version, "6.1.0")

if __name__ == '__main__':
    unittest.main()
