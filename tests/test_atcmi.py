import pytest
import aioblescan as aiobs
from aioblescan.plugins.atcmithermometer import *


@pytest.mark.parametrize(
    "data, temp, humidity, battery, battery_volts, counter",
    [
        (
            b"\x04>\x1d\x02\x01\x00\x008R@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@R8\x00\xf3%U\x0b\x9f\xde\xdb",
            24.3,
            37,
            85,
            2.975,
            222,
        ),
        (
            b"\x04>\x1d\x02\x01\x00\x008R@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@R8\x01\x08\x1aU\x0b\x9f\xe0\xd5",
            26.4,
            26,
            85,
            2.975,
            224,
        ),
        (
            b"\x04>\x1d\x02\x01\x00\x008R@8\xc1\xa4\x11\x10\x16\x1a\x18\xa4\xc18@R8\xff\xd3,B\n\xfe\xfb\xce",
            -4.5,
            44,
            66,
            2.814,
            251,
        ),
    ],
)
def test_foo(data, temp, humidity, battery, battery_volts, counter):
    ev = aiobs.HCI_Event()
    ev.decode(data)
    xx = ATCMiThermometer().decode(ev)
    assert temp == xx["temp"], "Wrong temperature C"
    assert humidity == xx["humidity"], "Wrong humidity %"
    assert battery == xx["battery"], "Wrong battery %"
    assert battery_volts == xx["battery_volts"], "Wrong battery V"
    assert counter == xx["counter"], "Wrong counter"
