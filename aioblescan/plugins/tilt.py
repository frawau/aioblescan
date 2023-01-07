#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deals with the Tilt formatted message
from struct import unpack
import json
import aioblescan as aios

# Tilt format based on iBeacon format with Tilt specific uuid preamble (a495)
TILT = "0215a495"


class Tilt(object):
    """
    Class defining the content of a Tilt advertisement
    """

    def decode(self, packet):
        data = {}
        raw_data = packet.retrieve("Manufacturer Specific Data")
        if raw_data:
            pckt = raw_data[0].payload[1].val
            payload = pckt.hex()
            mfg_id = payload[0:8]
            rssi = packet.retrieve("rssi")
            mac = packet.retrieve("peer")
            if mfg_id == TILT:
                data["uuid"] = payload[4:36]
                data["major"] = unpack(">H", pckt[18:20])[0]  # temperature in degrees F
                data["minor"] = unpack(">H", pckt[20:22])[0]  # specific gravity x1000
                data["tx_power"] = unpack(">b", pckt[22:23])[
                    0
                ]  # weeks since battery change (0-152 when converted to unsigned 8 bit integer) and other TBD operation codes
                data["rssi"] = rssi[-1].val
                data["mac"] = mac[-1].val
                return json.dumps(data)
