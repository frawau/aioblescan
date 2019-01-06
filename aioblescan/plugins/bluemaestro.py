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
        raw_data = packet.retrieve('Payload for mfg_specific_data')
        if raw_data:
            pckt = raw_data[0].val
            mfg_id = unpack('<H', pckt[:2])[0]
            if mfg_id == BLUEMAESTRO:
                data['version'] = unpack('<B', pckt[2:3])[0]
                data['batt_lvl'] = unpack('<B', pckt[3:4])[0]
                data['logging'] = unpack('>H', pckt[4:6])[0]
                data['interval'] = unpack('>H', pckt[6:8])[0]
                data['temperature'] = unpack('>h', pckt[8:10])[0]/10
                data['humidity'] = unpack('>h', pckt[10:12])[0]/10
                data['pressure'] = unpack('>h', pckt[12:14])[0]/10
        return data

