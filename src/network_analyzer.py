import scapy.all as scapy
import logging
from scapy.error import Scapy_Exception

logger = logging.getLogger(__name__)

def analyze_network_traffic(interface, duration=60):
    suspicious_patterns = [
        b'CVE-2023-38831',
        b'WinRAR vulnerability',
        b'exploit'
    ]

    def packet_callback(packet):
        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            for pattern in suspicious_patterns:
                if pattern in payload:
                    logger.warning(f"Suspicious network traffic detected: {pattern}")
                    return True
        return False

    try:
        scapy.sniff(iface=interface, prn=packet_callback, timeout=duration)
    except Scapy_Exception as e:
        logger.error(f"Scapy error during network traffic analysis: {str(e)}")
    except Exception as e:
        logger.error(f"Error during network traffic analysis: {str(e)}")

    return "network", False
