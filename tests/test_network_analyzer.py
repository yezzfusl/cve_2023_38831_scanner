import unittest
from unittest.mock import patch, MagicMock
from src.network_analyzer import analyze_network_traffic

class TestNetworkAnalyzer(unittest.TestCase):

    @patch('scapy.all.sniff')
    def test_analyze_network_traffic_suspicious(self, mock_sniff):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value.load = b'CVE-2023-38831 exploit'

        def side_effect(**kwargs):
            kwargs['prn'](mock_packet)
            return []

        mock_sniff.side_effect = side_effect

        result = analyze_network_traffic('eth0', duration=1)
        self.assertTrue(result)

    @patch('scapy.all.sniff')
    def test_analyze_network_traffic_clean(self, mock_sniff):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value.load = b'Clean traffic'

        def side_effect(**kwargs):
            kwargs['prn'](mock_packet)
            return []

        mock_sniff.side_effect = side_effect

        result = analyze_network_traffic('eth0', duration=1)
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()
