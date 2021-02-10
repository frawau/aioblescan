import pytest
import aioblescan as aiobs
from aioblescan.plugins.atcmithermometer import *


@pytest.mark.parametrize(
    "data, mac, temp, humidity, battery, battery_volts, counter, rssi",
    [
        (
            b"\x04>\x1d\x02\x01\x00\x008R@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@R8\x00\xf3%U\x0b\x9f\xde\xdb",
            "a4:c1:38:40:52:38",
            24.3,
            37,
            85,
            2.975,
            222,
            -37,
        ),
        (
            b"\x04>\x1d\x02\x01\x00\x009R@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@R9\x01\x08\x1aU\x0b\x9f\xe0\xd5",
            "a4:c1:38:40:52:39",
            26.4,
            26,
            85,
            2.975,
            224,
            -43,
        ),
        (
            b"\x04>\x1d\x02\x01\x00\x008S@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@S8\xff\xd3,B\n\xfe\xfb\xce",
            "a4:c1:38:40:53:38",
            -4.5,
            44,
            66,
            2.814,
            251,
            -50,
        ),
    ],
)
def test_some_packets(data, mac, temp, humidity, battery, battery_volts, counter, rssi):
    ev = aiobs.HCI_Event()
    ev.decode(data)
    xx = ATCMiThermometer().decode(ev)
    assert mac == xx["mac address"], "Wrong MAC addr"
    assert temp == xx["temperature"], "Wrong temperature C"
    assert humidity == xx["humidity"], "Wrong humidity %"
    assert battery == xx["battery"], "Wrong battery %"
    assert battery_volts == xx["battery_volts"], "Wrong battery V"
    assert counter == xx["counter"], "Wrong counter"
    assert rssi == xx["rssi"], "Wrong rssi"
