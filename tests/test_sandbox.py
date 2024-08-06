import unittest
from unittest.mock import patch, mock_open
from src.sandbox import Sandbox

class TestSandbox(unittest.TestCase):

    @patch('tempfile.mkdtemp')
    @patch('shutil.rmtree')
    def test_sandbox_context_manager(self, mock_rmtree, mock_mkdtemp):
        mock_mkdtemp.return_value = '/tmp/test_sandbox'
        with Sandbox() as sandbox:
            self.assertEqual(sandbox.temp_dir, '/tmp/test_sandbox')
        mock_rmtree.assert_called_once_with('/tmp/test_sandbox')

    @patch('subprocess.run')
    def test_run_command(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'Test output'
        mock_run.return_value.stderr = ''

        with Sandbox() as sandbox:
            returncode, stdout, stderr = sandbox.run_command(['echo', 'test'])

        self.assertEqual(returncode, 0)
        self.assertEqual(stdout, 'Test output')
        self.assertEqual(stderr, '')

    @patch('shutil.copy')
    def test_copy_file_to_sandbox(self, mock_copy):
        with Sandbox() as sandbox:
            sandbox.temp_dir = '/tmp/test_sandbox'
            result = sandbox.copy_file_to_sandbox('/path/to/file.txt')

        self.assertEqual(result, '/tmp/test_sandbox/file.txt')
        mock_copy.assert_called_once_with('/path/to/file.txt', '/tmp/test_sandbox')

if __name__ == '__main__':
    unittest.main()
