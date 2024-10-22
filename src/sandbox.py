import os
import subprocess
import tempfile
import shutil
import logging

logger = logging.getLogger(__name__)

class Sandbox:
    def __init__(self):
        self.temp_dir = None

    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp()
        logger.info(f"Created sandbox environment in {self.temp_dir}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            shutil.rmtree(self.temp_dir)
            logger.info(f"Removed sandbox environment {self.temp_dir}")

    def run_command(self, command):
        try:
            result = subprocess.run(command, cwd=self.temp_dir, capture_output=True, text=True, timeout=30)
            logger.info(f"Command executed in sandbox: {command}")
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out in sandbox: {command}")
            return -1, "", "Timeout"
        except Exception as e:
            logger.error(f"Error running command in sandbox: {str(e)}")
            return -1, "", str(e)

    def copy_file_to_sandbox(self, file_path):
        try:
            dest_path = os.path.join(self.temp_dir, os.path.basename(file_path))
            shutil.copy2(file_path, dest_path)
            logger.info(f"Copied {file_path} to sandbox")
            return dest_path
        except Exception as e:
            logger.error(f"Error copying file to sandbox: {str(e)}")
            return None
