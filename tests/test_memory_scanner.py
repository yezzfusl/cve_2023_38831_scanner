import unittest
from unittest.mock import patch, MagicMock
from src.memory_scanner import scan_process_memory

class TestMemoryScanner(unittest.TestCase):

    @patch('psutil.process_iter')
    @patch('psutil.Process')
    def test_scan_process_memory_suspicious(self, mock_process, mock_process_iter):
        mock_process_iter.return_value = [MagicMock(info={'name': 'WinRAR.exe', 'pid': 1234})]
        mock_process.return_value.memory_maps.return_value = [MagicMock(addr='0x1000', size=1024)]
        mock_process.return_value.memory_maps.return_value[0].read.return_value = b'CVE-2023-38831 exploit'

        result = scan_process_memory('WinRAR.exe')
        self.assertTrue(result)

    @patch('psutil.process_iter')
    @patch('psutil.Process')
    def test_scan_process_memory_clean(self, mock_process, mock_process_iter):
        mock_process_iter.return_value = [MagicMock(info={'name': 'WinRAR.exe', 'pid': 1234})]
        mock_process.return_value.memory_maps.return_value = [MagicMock(addr='0x1000', size=1024)]
        mock_process.return_value.memory_maps.return_value[0].read.return_value = b'Clean memory'

        result = scan_process_memory('WinRAR.exe')
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
