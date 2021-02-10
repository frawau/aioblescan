#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deal with EddyStone formated message
#
# Copyright (c) 2017 François Wautier
#
# Note part of this code was adapted from PyBeacon (https://github.com/nirmankarta/PyBeacon)
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
from urllib.parse import urlparse
from enum import Enum

#
EDDY_UUID = b"\xfe\xaa"  # Google UUID


class ESType(Enum):
    """Enumerator for Eddystone types."""

    uid = 0x00
    url = 0x10
    tlm = 0x20
    eid = 0x30


url_schemes = [
    ("http", True),
    ("https", True),
    ("http", False),
    ("https", False),
]

url_domain = ["com", "org", "edu", "net", "info", "biz", "gov"]


class EddyStone(object):
    """Class defining the content of an EddyStone advertisement.

    Here the param type will depend on the type.

    For URL it should be a string with a compatible URL.

    For UID it is a dictionary with 2 keys, "namespace" and "instance", values are bytes .

    For TLM it shall be an dictionary with 4 keys: "battery","temperature", "count" and "uptime".
    Any missing key shall be replaced by its default value.

    For EID it should me a bytes string of length 8

        :param type: The type of EddyStone advertisement. From ESType
        :type type: ESType
        :oaram param: The payload corresponding to the type

    """

    def __init__(self, type=ESType.url, param="https://goo.gl/m9UiEA"):
        self.power = 0
        self.payload = (
            []
        )  # As defined in https://github.com/google/eddystone/blob/master/protocol-specification.md
        self.payload.append(aios.Byte("Flag Length", b"\x02"))
        self.payload.append(aios.Byte("Flag Data Type", b"\x01"))
        self.payload.append(aios.Byte("Flag Data", b"\x1a"))
        self.payload.append(aios.Byte("Length UUID services", b"\x03"))
        self.payload.append(aios.Byte("Complete List UUID Service", b"\x03"))
        self.payload.append(aios.Byte("Eddystone UUID", b"\xaa"))
        self.payload.append(aios.Byte("...", b"\xfe"))
        self.service_data_length = aios.IntByte("Service Data length", 4)
        self.payload.append(self.service_data_length)
        self.payload.append(aios.Byte("Service Data data type value", b"\x16"))
        self.payload.append(aios.Byte("Eddystone UUID", b"\xaa"))
        self.payload.append(aios.Byte("...", b"\xfe"))
        self.type = aios.EnumByte(
            "type",
            type.value,
            {
                ESType.uid.value: "Eddystone-UID",
                ESType.url.value: "Eddystone-URL",
                ESType.tlm.value: "Eddystone-TLM",
                ESType.eid.value: "Eddystone-EID",
            },
        )
        self.payload.append(self.type)
        self.parsed_payload = b""
        self.type_payload = param

    def change_type(self, type, param):
        self.type.val = type.value
        self.type_payload = param
        self.service_data_length.val = 4
        self.parsed_payload = b""

    def change_type_payload(self, param):
        self.type_payload = param
        self.service_data_length.val = 4
        self.parsed_payload = b""

    def url_encoder(self):
        encodedurl = []
        encodedurl.append(aios.IntByte("Tx Power", self.power))
        asisurl = ""
        myurl = urlparse(self.type_payload)
        myhostname = myurl.hostname
        mypath = myurl.path
        if (myurl.scheme, myhostname.startswith("www.")) in url_schemes:
            encodedurl.append(
                aios.IntByte(
                    "URL Scheme",
                    url_schemes.index((myurl.scheme, myhostname.startswith("www."))),
                )
            )
            if myhostname.startswith("www."):
                myhostname = myhostname[4:]
        extval = None
        if myhostname.split(".")[-1] in url_domain:
            extval = url_domain.index(myhostname.split(".")[-1])
            myhostname = ".".join(myhostname.split(".")[:-1])
        if extval is not None and not mypath.startswith("/"):
            extval += 7
        else:
            if myurl.port is None:
                if extval is not None:
                    mypath = mypath[1:]
            else:
                extval += 7
        encodedurl.append(aios.String("URL string"))
        encodedurl[-1].val = myhostname
        if extval is not None:
            encodedurl.append(aios.IntByte("URL Extention", extval))

        if myurl.port:
            asisurl += ":" + str(myurl.port) + mypath
        asisurl += mypath
        if myurl.params:
            asisurl += ";" + myurl.params
        if myurl.query:
            asisurl += "?" + myurl.query
        if myurl.fragment:
            asisurl += "#" + myurl.fragment
        encodedurl.append(aios.String("Rest of URL"))
        encodedurl[-1].val = asisurl
        tlength = 0
        for x in encodedurl:  # Check the payload length
            tlength += len(x)
        if tlength > 19:  # Actually 18 but we have tx power
            raise Exception("Encoded url too long (max 18 bytes)")
        self.service_data_length.val += tlength  # Update the payload length
        return encodedurl

    def uid_encoder(self):
        encodedurl = []
        encodedurl.append(aios.IntByte("Tx Power", self.power))
        encodedurl.append(aios.NBytes("Namespace", 10))
        encodedurl[-1].val = self.type_payload["namespace"]
        encodedurl.append(aios.NBytes("Instance", 6))
        encodedurl[-1].val = self.type_payload["instance"]
        encodedurl.append(aios.NBytes("RFU", 2))
        encodedurl[-1].val = b"\x00\x00"
        self.service_data_length.val = (
            23  # Update the payload length/ways the same for uid
        )
        return encodedurl

    def tlm_encoder(self):
        encodedurl = []
        encodedurl.append(aios.NBytes("VBATT", 2))
        if "battery" in self.type_payload:
            encodedurl[-1].val = self.type_payload["battery"]
        else:
            encodedurl[-1].val = -128
        encodedurl.append(aios.Float88("Temperature"))
        if "temperature" in self.type_payload:
            encodedurl[-1].val = self.type_payload["temperature"]
        else:
            encodedurl[-1].val = -128

        encodedurl.append(aios.ULongInt("Count"))
        if "count" in self.type_payload:
            encodedurl[-1].val = self.type_payload["count"]
        else:
            encodedurl[-1].val = 0

        encodedurl.append(aios.ULongInt("Uptime"))
        if "uptime" in self.type_payload:
            encodedurl[-1].val = self.type_payload["uptime"]
        else:
            encodedurl[-1].val = 0
        return encodedurl

    def eid_encoder(self):
        encodedurl = []
        encodedurl.append(aios.IntByte("Tx Power", self.power))
        encodedurl.append(aios.NBytes("Namespace", 8))
        encodedurl[-1].val = self.type_payload
        self.service_data_length.val = 13
        return encodedurl

    def encode(self):
        # Generate the payload
        if self.type.val == ESType.uid.value:
            espayload = self.uid_encoder()
        elif self.type.val == ESType.url.value:
            espayload = self.url_encoder()
        elif self.type.val == ESType.tlm.value:
            espayload = self.tlm_encoder()
        elif self.type.val == ESType.eid.value:
            espayload = self.eid_encoder()
        encmsg = b""
        for x in self.payload + espayload:
            encmsg += x.encode()
        mylen = aios.IntByte("Length", len(encmsg))
        encmsg = mylen.encode() + encmsg
        for x in range(32 - len(encmsg)):
            encmsg += b"\x00"
        return encmsg

    def decode(self, packet):
        """Check a parsed packet and figure out if it is an Eddystone Beacon.
        If it is , return the relevant data as a dictionary.

        Return None, it is not an Eddystone Beacon advertising packet"""

        ssu = packet.retrieve("Complete uuids")
        found = False
        for x in ssu:
            if EDDY_UUID in x:
                found = True
                break
        if not found:
            return None

        found = False
        adv = packet.retrieve("Advertised Data")
        for x in adv:
            luuid = x.retrieve("Service Data uuid")
            for uuid in luuid:
                if EDDY_UUID == uuid:
                    found = x
                    break
            if found:
                break

        if not found:
            return None

        try:
            top = found.retrieve("Adv Payload")[0]
        except:
            return None
        # Rebuild that part of the structure
        found.payload.remove(top)
        # Now decode
        result = {}
        data = top.val
        etype = aios.EnumByte(
            "type",
            self.type.val,
            {
                ESType.uid.value: "Eddystone-UID",
                ESType.url.value: "Eddystone-URL",
                ESType.tlm.value: "Eddystone-TLM",
                ESType.eid.value: "Eddystone-EID",
            },
        )
        data = etype.decode(data)
        found.payload.append(etype)
        if etype.val == ESType.uid.value:
            power = aios.IntByte("tx_power")
            data = power.decode(data)
            found.payload.append(power)
            result["tx_power"] = power.val

            nspace = aios.Itself("namespace")
            xx = nspace.decode(
                data[:10]
            )  # According to https://github.com/google/eddystone/tree/master/eddystone-uid
            data = data[10:]
            found.payload.append(nspace)
            result["name space"] = nspace.val

            nspace = aios.Itself("instance")
            xx = nspace.decode(
                data[:6]
            )  # According to https://github.com/google/eddystone/tree/master/eddystone-uid
            data = data[6:]
            found.payload.append(nspace)
            result["instance"] = nspace.val

        elif etype.val == ESType.url.value:
            power = aios.IntByte("tx_power")
            data = power.decode(data)
            found.payload.append(power)
            result["tx_power"] = power.val

            url = aios.EnumByte(
                "type",
                0,
                {
                    0x00: "http://www.",
                    0x01: "https://www.",
                    0x02: "http://",
                    0x03: "https://",
                },
            )
            data = url.decode(data)
            result["url"] = url.strval
            for x in data:
                if bytes([x]) == b"\x00":
                    result["url"] += ".com/"
                elif bytes([x]) == b"\x01":
                    result["url"] += ".org/"
                elif bytes([x]) == b"\x02":
                    result["url"] += ".edu/"
                elif bytes([x]) == b"\x03":
                    result["url"] += ".net/"
                elif bytes([x]) == b"\x04":
                    result["url"] += ".info/"
                elif bytes([x]) == b"\x05":
                    result["url"] += ".biz/"
                elif bytes([x]) == b"\x06":
                    result["url"] += ".gov/"
                elif bytes([x]) == b"\x07":
                    result["url"] += ".com"
                elif bytes([x]) == b"\x08":
                    result["url"] += ".org"
                elif bytes([x]) == b"\x09":
                    result["url"] += ".edu"
                elif bytes([x]) == b"\x10":
                    result["url"] += ".net"
                elif bytes([x]) == b"\x11":
                    result["url"] += ".info"
                elif bytes([x]) == b"\x12":
                    result["url"] += ".biz"
                elif bytes([x]) == b"\x13":
                    result["url"] += ".gov"
                else:
                    result["url"] += chr(x)  # x.decode("ascii") #Yep ASCII only
                    url = aios.String("url")
            url.decode(result["url"])
            found.payload.append(url)
        elif etype.val == ESType.tlm.value:
            myinfo = aios.IntByte("version")
            data = myinfo.decode(data)
            found.payload.append(myinfo)
            myinfo = aios.ShortInt("battery")
            data = myinfo.decode(data)
            result["battery"] = myinfo.val
            found.payload.append(myinfo)
            myinfo = aios.Float88("temperature")
            data = myinfo.decode(data)
            found.payload.append(myinfo)
            result["temperature"] = myinfo.val
            myinfo = aios.LongInt("pdu count")
            data = myinfo.decode(data)
            found.payload.append(myinfo)
            result["pdu count"] = myinfo.val
            myinfo = aios.LongInt("uptime")
            data = myinfo.decode(data)
            found.payload.append(myinfo)
            result["uptime"] = myinfo.val * 100  # in msecs
            return result
        # elif etype.val== ESType.tlm.eid:
        else:
            result["data"] = data
            xx = Itself("data")
            xx.decode(data)
            found.payload.append(xx)

        rssi = packet.retrieve("rssi")
        if rssi:
            result["rssi"] = rssi[-1].val
        mac = packet.retrieve("peer")
        if mac:
            result["mac address"] = mac[-1].val
        return result
