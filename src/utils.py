import os
import winreg
import logging

logger = logging.getLogger(__name__)

def get_winrar_path():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinRAR") as key:
            path = winreg.QueryValueEx(key, "exe64")[0]
        return path if os.path.exists(path) else None
    except WindowsError:
        logger.error("Unable to find WinRAR installation path")
        return None
