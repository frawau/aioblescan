#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deal with RuuviTag formated message
#
# Copyright (c) 2017 François Wautier
#
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

import aioblescan as aios
from base64 import b64decode
from math import sqrt
from struct import pack, unpack, calcsize
from aioblescan.plugins import EddyStone
# A few convenience functions
#

# Ruuvi tag stuffs

class RuuviWeather(object):
    """Class defining the content of an Ruuvi Tag advertisement.


    """

    def __init__(self):
        self.temp= 0
        self.humidity = 0
        self.pressure = 0
        self.accel_x = 0
        self.accel_y = 0
        self.accel_z = 0

    def decode(self,packet):
        #Look for Ruuvi tag URL and decode it
        result={}
        url=EddyStone().decode(packet)
        if url is None:
            url=packet.retrieve("Payload for mfg_specific_data")
            if url:
                val=url[0].val
                if val[0]==0x99 and val[1]==0x04 and val[2]==0x03:
                    #Looks just right
                    result["mac address"]=packet.retrieve("peer")[0].val
                    val=val[2:]
                    result["humidity"]=val[1]/2.0
                    result["temperature"]=unpack(">b",int(val[2]).to_bytes(1,"big"))[0]
                    result["temperature"]+=val[3]/100.0
                    result["pressure"]=int.from_bytes(val[4:6],"big")+50000
                    dx=int.from_bytes(val[6:8],"big",signed=True)
                    dy=int.from_bytes(val[8:10],"big",signed=True)
                    dz=int.from_bytes(val[10:12],"big",signed=True)
                    length=sqrt(dx**2 + dy**2 + dz**2)
                    result["accelerometer"]=(dx,dy,dz,length)
                    result["voltage"]=int.from_bytes(val[12:14],"big")
                    return result

            else:
                return None
        rssi=packet.retrieve("rssi")
        if rssi:
            result["rssi"]=rssi[-1].val
        power=packet.retrieve("tx_power")
        if power:
            result["tx_power"]=power[-1].val
        try:
            if "//ruu.vi/" in url["url"]:
                #We got a live one
                result["mac address"]=packet.retrieve("peer")[0].val
                url=url["url"].split("//ruu.vi/#")[-1]
                if len(url)>8:
                    url=url[:-1]
                val=b64decode(url+ '=' * (4 - len(url) % 4),"#.")
                if val[0] in [2,4]:
                    result["humidity"]=val[1]/2.0
                    result["temperature"]=unpack(">b",int(val[2]).to_bytes(1,"big"))[0] #Signed int...
                    result["pressure"]=int.from_bytes(val[4:6],"big")+50000
                    if val[0] == 4:
                        try:
                            result["id"]=val[6]
                        except:
                            pass
                    return result
                elif val[0] == 3:
                    result["humidity"]=val[1]/2.0
                    result["temperature"]=unpack(">b",int(val[2]).to_bytes(1,"big"))[0]
                    result["temperature"]+=val[3]/100.0
                    result["pressure"]=int.from_bytes(val[4:6],"big")+50000
                    dx=int.from_bytes(val[6:8],"big",signed=True)
                    dy=int.from_bytes(val[8:10],"big",signed=True)
                    dz=int.from_bytes(val[10:12],"big",signed=True)
                    length=sqrt(dx**2 + dy**2 + dz**2)
                    result["accelerometer"]=(dx,dy,dz,length)
                    result["voltage"]=int.from_bytes(val[12:14],"big")
                    return result
        except:
            print ("\n\nurl oops....")
            packet.show()
        return None
