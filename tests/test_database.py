import unittest
from unittest.mock import patch, MagicMock
from src.database import Database

class TestDatabase(unittest.TestCase):

    @patch('sqlite3.connect')
    def test_connect(self, mock_connect):
        db = Database(':memory:')
        db.connect()
        mock_connect.assert_called_once_with(':memory:')

    @patch('sqlite3.connect')
    def test_create_table(self, mock_connect):
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        db = Database(':memory:')
        db.create_table()

        mock_conn.execute.assert_called_once()
        self.assertIn('CREATE TABLE IF NOT EXISTS scan_results', mock_conn.execute.call_args[0][0])

    @patch('sqlite3.connect')
    def test_insert_scan_result(self, mock_connect):
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        db = Database(':memory:')
        db.insert_scan_result(True, '6.0.2', 'Pass', 'Clean', 'Clean', 'No issues')

        mock_conn.execute.assert_called_once()
        self.assertIn('INSERT INTO scan_results', mock_conn.execute.call_args[0][0])

    @patch('sqlite3.connect')
    def test_get_all_scan_results(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.execute.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        db = Database(':memory:')
        db.get_all_scan_results()

        mock_conn.execute.assert_called_once_with("SELECT * FROM scan_results ORDER BY timestamp DESC")
        mock_cursor.fetchall.assert_called_once()

if __name__ == '__main__':
    unittest.main()
