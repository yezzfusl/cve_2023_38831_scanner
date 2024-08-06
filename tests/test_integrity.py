import unittest
from unittest.mock import patch, mock_open
from src.integrity import calculate_file_hash, check_file_integrity

class TestIntegrity(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data=b"test data")
    def test_calculate_file_hash(self, mock_file):
        expected_hash = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        calculated_hash = calculate_file_hash("dummy_path")
        self.assertEqual(calculated_hash, expected_hash)

    @patch("src.integrity.calculate_file_hash")
    def test_check_file_integrity_pass(self, mock_calculate_hash):
        mock_calculate_hash.return_value = "e33a16be6b60496721f01deb9562e9d2ad76f03feebf8d0144f9da92dc2839e1"
        self.assertTrue(check_file_integrity("dummy_path"))

    @patch("src.integrity.calculate_file_hash")
    def test_check_file_integrity_fail(self, mock_calculate_hash):
        mock_calculate_hash.return_value = "invalid_hash"
        self.assertFalse(check_file_integrity("dummy_path"))

if __name__ == '__main__':
    unittest.main()
