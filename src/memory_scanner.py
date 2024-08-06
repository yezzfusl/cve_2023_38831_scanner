import psutil
import re
import logging

def scan_process_memory(process_name):
    suspicious_patterns = [
        rb'CVE-2023-38831',
        rb'WinRAR vulnerability',
        rb'exploit'
    ]

    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'] == process_name:
            pid = proc.info['pid']
            try:
                process = psutil.Process(pid)
                memory_maps = process.memory_maps(grouped=False)
                
                for mem in memory_maps:
                    try:
                        content = process.memory_maps()[0].read(mem.addr, mem.size)
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content):
                                logging.warning(f"Suspicious pattern found in process memory: {pattern}")
                                return True
                    except psutil.AccessDenied:
                        logging.warning(f"Access denied to memory region of process {pid}")
                    except Exception as e:
                        logging.error(f"Error scanning memory: {str(e)}")
            except psutil.NoSuchProcess:
                logging.error(f"Process {pid} no longer exists")
            except Exception as e:
                logging.error(f"Error accessing process {pid}: {str(e)}")

    return False
