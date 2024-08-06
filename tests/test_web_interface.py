import unittest
from unittest.mock import patch, MagicMock
from src.web_interface import app

class TestWebInterface(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()

    def test_index_route(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'CVE-2023-38831 Scanner', response.data)

    @patch('src.web_interface.scan_for_cve_2023_38831')
    @patch('src.web_interface.db.insert_scan_result')
    def test_scan_route(self, mock_insert, mock_scan):
        mock_scan.return_value = (True, '6.0.2')
        
        response = self.app.post('/scan')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'success', response.data)
        self.assertIn(b'true', response.data)
        self.assertIn(b'6.0.2', response.data)
        
        mock_insert.assert_called_once()

    @patch('src.web_interface.db.get_all_scan_results')
    def test_results_route(self, mock_get_results):
        mock_get_results.return_value = [
            (1, '2023-08-06 12:00:00', True, '6.0.2', 'Pass', 'Clean', 'Clean', 'No issues')
        ]
        
        response = self.app.get('/results')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan Results', response.data)
        self.assertIn(b'2023-08-06 12:00:00', response.data)
        self.assertIn(b'6.0.2', response.data)

if __name__ == '__main__':
    unittest.main()
