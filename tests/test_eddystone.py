import unittest
import aioblescan
from aioblescan.plugins import EddyStone


class EddystoneURL(unittest.TestCase):
    def test_eddystone_url(self):
        pckt = aioblescan.HCI_Event()
        pckt.decode(
            b'\x04>)\x02\x01\x03\x01\xdc)e\x90U\xf1\x1d\x02\x01\x06\x03\x03\xaa\xfe\x15\x16\xaa\xfe\x10\xf6\x03makecode\x00#about\xb5')
        result = EddyStone().decode(pckt)
        self.assertDictEqual(result, {'mac address': 'f1:55:90:65:29:dc',
                                      'tx_power': -10,
                                      'url': 'https://makecode.com/#about',
                                      'rssi': -75})


class EddystoneEID(unittest.TestCase):
    def test_eddystone_uid(self):
        pckt = aioblescan.HCI_Event()
        pckt.decode(
            b'\x04>)\x02\x01\x03\x01\xdc)e\x90U\xf1\x1d\x02\x01\x06\x03\x03\xaa\xfe\x15\x16\xaa\xfe\x00\xf6\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x00\x00\x00\x00\x00X\xb6')
        result = EddyStone().decode(pckt)
        self.assertDictEqual(result, {'tx_power': -10,
                                      'rssi': -74,
                                      'name space': (0x63).to_bytes(10,byteorder="big"),
                                      'instance': (0x58).to_bytes(6,byteorder="big"),
                                      'mac address': 'f1:55:90:65:29:dc'})


if __name__ == '__main__':
    unittest.main()
