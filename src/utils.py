import os
import winreg

def get_winrar_path():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinRAR")
        path = winreg.QueryValueEx(key, "exe64")[0]
        winreg.CloseKey(key)
        return path if os.path.exists(path) else None
    except WindowsError:
        return None
