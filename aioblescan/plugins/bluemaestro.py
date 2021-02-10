#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deals with the Blue Maestro formatted message
from struct import unpack
import aioblescan as aios

BLUEMAESTRO = 307


class BlueMaestro(object):
    """
    Class defining the content of a Blue Maestro advertisement
    """

    def decode(self, packet):
        data = {}
        raw_data = packet.retrieve("Manufacturer Specific Data")
        try:
            raw_data = raw_data.payload
            if raw_data:
                mfg_id = raw_data[0].val
                if mfg_id == BLUEMAESTRO:
                    pckt = raw_data[1].val
                    data["version"] = unpack("<B", pckt[0:1])[0]
                    data["batt_lvl"] = unpack("<B", pckt[1:2])[0]
                    data["logging"] = unpack(">H", pckt[2:4])[0]
                    data["interval"] = unpack(">H", pckt[4:6])[0]
                    data["temperature"] = unpack(">h", pckt[6:8])[0] / 10
                    data["humidity"] = unpack(">h", pckt[8:10])[0] / 10
                    data["pressure"] = unpack(">h", pckt[10:12])[0] / 10
        except:
            pass
        return data
