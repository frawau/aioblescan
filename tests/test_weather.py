import unittest
from aioblescan.plugins.ruuviweather import get_temp


class Weather(unittest.TestCase):
    def test_decode_temperature(self):
        values = [[0x00, 0x00, 0.0],
                  [0x81, 0x45, -1.69],
                  [0x01, 0x45, 1.69]]
        for inter, fract, result in values:
            self.assertEqual(result, get_temp(inter, fract))


if __name__ == '__main__':
    unittest.main()
