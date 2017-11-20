import unittest
import aioblescan


class IntByte(unittest.TestCase):
    def test_decode(self):
        int_byte_class = aioblescan.IntByte('TestData')
        new_data = int_byte_class.decode(b'\x10\xf6\x03')
        self.assertEqual(b'\xf6\x03', new_data)
        self.assertEqual(16, int_byte_class.val)
        self.assertEqual('TestData', int_byte_class.name)


class MacAddr(unittest.TestCase):
    def test_decode(self):
        mac_addr = aioblescan.MACAddr('TestAddr', '12:23:45:67:89:AB:CD')
        new_data = mac_addr.decode(b'k\xa0\xd0.\x04\xf8\x1f\x02\x01\x00')
        self.assertEqual('f8:04:2e:d0:a0:6b', mac_addr.val)
        self.assertEqual(b'\x1f\x02\x01\x00', new_data)


if __name__ == '__main__':
    unittest.main()
