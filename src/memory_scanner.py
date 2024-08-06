import psutil
import re
import logging

logger = logging.getLogger(__name__)

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
                                logger.warning(f"Suspicious pattern found in process memory: {pattern}")
                                return "memory", True
                    except psutil.AccessDenied:
                        logger.warning(f"Access denied to memory region of process {pid}")
                    except Exception as e:
                        logger.error(f"Error scanning memory: {str(e)}")
            except psutil.NoSuchProcess:
                logger.error(f"Process {pid} no longer exists")
            except Exception as e:
                logger.error(f"Error accessing process {pid}: {str(e)}")

    return "memory", False
