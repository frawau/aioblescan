#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deals with Thermobeacon formatted messages
#
# Copyright (c) 2021 Will Cooke @8none1
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE


def parse(packet):
    peer = packet.retrieve("peer")
    rssi = packet.retrieve("rssi")
    uuid = packet.retrieve("Incomplete uuids")
    payload = packet.retrieve("Manufacturer Specific Data")

    if peer and rssi and payload and uuid:
        uuid = uuid[0].lonbytes[0].val
        payload = payload[0].payload[1].val

        if b"\xff\xf0" == uuid:
            mac = peer[0].val
            rssi = rssi[0].val
            mac_in_payload = ":".join("%02x" % x for x in payload[7:1:-1])
            if mac == mac_in_payload:
                return parse_payload(mac, rssi, payload)


def parse_payload(mac, rssi, payload):
    if len(payload) == 18:
        battery_volts = int.from_bytes(payload[8:10], "little")
        temp = int.from_bytes(payload[10:12], "little", signed=True) / 16.0
        humidity = int.from_bytes(payload[12:14], "little", signed=True) / 16.0
        counter = int.from_bytes(payload[14:18], "little")
        return {
            "mac address": mac,
            "temperature": temp,
            "humidity": humidity,
            "battery_volts": battery_volts,
            "counter": counter,
            "rssi": rssi,
        }
    elif len(payload) == 20:
        max_temp = int.from_bytes(payload[8:10], "little") / 16.0
        max_temp_ts = int.from_bytes(payload[10:14], "little")
        min_temp = int.from_bytes(payload[14:16], "little") / 16.0
        min_temp_ts = int.from_bytes(payload[16:20], "little")
        return {
            "mac address": mac,
            "max_temperature": max_temp,
            "min_temperature": min_temp,
            "max_temp_ts": max_temp_ts,
            "min_temp_ts": min_temp_ts,
        }
    else:
        return False


class ThermoBeacon(object):
    """Class defining the content of a ThermoBeacon advertisement."""

    def decode(self, packet):
        result = parse(packet)
        if result:
            return result
