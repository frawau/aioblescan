#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is simply a python only Bluetooth LE Scan command with
# decoding of advertised packets
#
# Copyright (c) 2017 François Wautier
#
# Note large part of this code was taken from scapy and other opensource software
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

import socket, asyncio, sys
from struct import pack, unpack, calcsize


#A little bit of HCI
HCI_COMMAND = 0x01
HCI_ACL_DATA = 0x02
HCI_SCO_DATA = 0x03
HCI_EVENT = 0x04
HCI_VENDOR = 0x05

PRINT_INDENT="    "

CMD_SCAN_REQUEST = 0x200c #mixing the OGF in with that HCI shift

#
EDDY_UUID=b"\xfe\xaa"    #Google UUID

#Generated from https://www.uuidgenerator.net/ 906ed6ab-6785-4eab-9847-bf9889c098ae alternative is 668997f8-4acd-48ea-b35b-749e54215860
MY_UUID = b'\x90\x6e\xd6\xab\x67\x85\x4e\xab\x98\x47\xbf\x98\x89\xc0\x98\xae'
#MY_UUID = b'\x66\x89\x97\xf8\x4a\xcd\x48\xea\xb3\x5b\x74\x9e\x54\x21\x58\x60'
#
# Let's define some useful types
#
class MACAddr:
    """Class representing a MAC address.

        :param name: The name of the instance
        :type name: str
        :param mac: the mac address.
        :type mac: str
        :returns: MACAddr instance.
        :rtype: MACAddr

    """
    def __init__(self,name,mac="00:00:00:00:00:00"):
        self.name = name
        self.val=mac.lower()

    def encode (self):
        """Encode the MAC address to a byte array.

            :returns: The encoded version of the MAC address
            :rtype: bytes
        """
        return int(self.val.replace(":",""),16).to_bytes(6,"little")

    def decode(self,data):
        """Decode the MAC address from a byte array.

        This will take the first 6 bytes from data and transform them into a MAC address
        string representation. This will be assigned to the attribute "val". It then returns
        the data stream minus the bytes consumed

            :param data: The data stream containing the value to decode at its head
            :type data: bytes
            :returns: The datastream minus the bytes consumed
            :rtype: bytes
        """
        self.val=':'.join(a + b for a, b in list(zip(*[iter(data[:6].hex())]*2))[::-1])
        return data[6:]

    def __len__(self):
        return 6

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class Bool:
    """Class representing a boolean value.

        :param name: The name of the instance
        :type name: str
        :param val: the boolean value.
        :type mac: bool
        :returns: Bool instance.
        :rtype: Bool

    """
    def __init__(self,name,val=True):
        self.name=name
        self.val=val

    def encode (self):
        val=(self.val and b'\x01') or b'\x00'
        return val

    def decode(self,data):
        self.val= data[:1]==b"\x01"
        return data[1:]

    def __len__(self):
        return 1

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class Byte:
    """Class representing a single byte value.

        :param name: The name of the instance
        :type name: str
        :param val: the single byte value.
        :type val: byte
        :returns: Byte instance.
        :rtype: Byte

    """
    def __init__(self,name,val=0):
        self.name=name
        self.val=val

    def encode (self):
        val=pack("<c",self.val)
        return val

    def decode(self,data):
        self.val= unpack("<c",data[:1])[0]
        return data[1:]

    def __len__(self):
        return 1

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),":".join(map(lambda b: format(b, "02x"), self.val))))

class EnumByte:
    """Class representing a single byte value from a limited set of value

        :param name: The name of the instance
        :type name: str
        :param val: the single byte value.
        :type val: byte
        :param loval: the list of possible values.
        :type loval: dict
        :returns: EnumByte instance.
        :rtype: EnumByte

    """
    def __init__(self,name,val=0,loval={0:"Undef"}):
        self.name=name
        self.val=val
        self.loval=loval

    def encode (self):
        val=pack(">B",self.val)
        return val

    def decode(self,data):
        self.val= unpack(">B",data[:1])[0]
        return data[1:]

    @property
    def strval(self):
        if self.val in self.loval:
            return self.loval[self.val]
        else:
            return str(self.val)

    def __len__(self):
        return 1

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        if self.val in self.loval:
            print("{}{}".format(PRINT_INDENT*(depth+1),self.loval[self.val]))
        else:
            print("{}Undef".format(PRINT_INDENT*(depth+1)))

class BitFieldByte:
    """Class representing a single byte value as a bit field.

        :param name: The name of the instance
        :type name: str
        :param val: the single byte value.
        :type val: byte
        :param loval: the list defining the name of the property represented by each bit.
        :type loval: list
        :returns: BitFieldByte instance.
        :rtype: BitFieldByte

    """
    def __init__(self,name,val=0,loval=["Undef"]*8):
        self.name=name
        self._val=val
        self.loval=loval

    def encode (self):
        val=pack(">B",self._val)
        return val

    def decode(self,data):
        self._val= unpack(">B",data[:1])[0]
        return data[1:]

    def __len__(self):
        return 1

    @property
    def val(self):
        resu={}
        for x in self.loval:
            if x not in ["Undef","Reserv"]:
                resu[x]=(self._val & mybit)>0
        return resu

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        mybit=0x80
        for x in self.loval:
            if x not in ["Undef","Reserv"]:
                print("{}{}: {}".format(PRINT_INDENT*(depth+1),x, ((self._val & mybit) and "True") or False))
            mybit = mybit >>1

class IntByte:
    """Class representing a single byte as a signed integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :returns: IntByte instance.
        :rtype: IntByte

    """
    def __init__(self,name,val=0):
        self.name=name
        self.val=val

    def encode (self):
        val=pack(">b",self.val)
        return val

    def decode(self,data):
        self.val= unpack(">b",data[:1])[0]
        return data[1:]

    def __len__(self):
        return 1

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class UIntByte:
    """Class representing a single byte as an unsigned integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :returns: UIntByte instance.
        :rtype: UIntByte

    """
    def __init__(self,name,val=0):
        self.name=name
        self.val=val

    def encode (self):
        val=pack(">B",self.val)
        return val

    def decode(self,data):
        self.val= unpack(">B",data[:1])[0]
        return data[1:]

    def __len__(self):
        return 1

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class ShortInt:
    """Class representing 2 bytes as a signed integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :param endian: Endianess of the bytes. "big" or no "big" (i.e. "little")
        :type endian: str
        :returns: ShortInt instance.
        :rtype: ShortInt

    """
    def __init__(self,name,val=0,endian="big"):
        self.name=name
        self.val=val
        self.endian = endian

    def encode (self):
        if self.endian == "big":
            val=pack(">h",self.val)
        else:
            val=pack("<h",self.val)
        return val

    def decode(self,data):
        if self.endian == "big":
            self.val= unpack(">h",data[:2])[0]
        else:
            self.val= unpack("<h",data[:2])[0]
        return data[2:]

    def __len__(self):
        return 2

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class UShortInt:
    """Class representing 2 bytes as an unsigned integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :param endian: Endianess of the bytes. "big" or no "big" (i.e. "little")
        :type endian: str
        :returns: UShortInt instance.
        :rtype: UShortInt

    """
    def __init__(self,name,val=0,endian="big"):
        self.name=name
        self.val=val
        self.endian = endian

    def encode (self):
        if self.endian == "big":
            val=pack(">H",self.val)
        else:
            val=pack("<H",self.val)
        return val

    def decode(self,data):
        if self.endian == "big":
            self.val= unpack(">H",data[:2])[0]
        else:
            self.val= unpack("<H",data[:2])[0]
        return data[2:]

    def __len__(self):
        return 2

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class LongInt:
    """Class representing 4 bytes as a signed integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :param endian: Endianess of the bytes. "big" or no "big" (i.e. "little")
        :type endian: str
        :returns: LongInt instance.
        :rtype: LongInt

    """
    def __init__(self,name,val=0,endian="big"):
        self.name=name
        self.val=val
        self.endian = endian

    def encode (self):
        if self.endian == "big":
            val=pack(">l",self.val)
        else:
            val=pack("<l",self.val)
        return val

    def decode(self,data):
        if self.endian == "big":
            self.val= unpack(">l",data[:4])[0]
        else:
            self.val= unpack("<l",data[:4])[0]
        return data[4:]

    def __len__(self):
        return 4

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class ULongInt:
    """Class representing 4 bytes as an unsigned integer.

        :param name: The name of the instance
        :type name: str
        :param val: the integer value.
        :type val: int
        :param endian: Endianess of the bytes. "big" or no "big" (i.e. "little")
        :type endian: str
        :returns: ULongInt instance.
        :rtype: ULongInt

    """
    def __init__(self,name,val=0,endian="big"):
        self.name=name
        self.val=val
        self.endian = endian

    def encode (self):
        if self.endian == "big":
            val=pack(">L",self.val)
        else:
            val=pack("<L",self.val)
        return val

    def decode(self,data):
        if self.endian == "big":
            self.val= unpack(">L",data[:4])[0]
        else:
            self.val= unpack("<L",data[:4])[0]
        return data[4:]

    def __len__(self):
        return 4

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class OgfOcf:
    """Class representing the 2 bytes that specify the command in an HCI command packet.

        :param name: The name of the instance
        :type name: str
        :param ogf: the Op-code Group (6 bits).
        :type ogf: bytes
        :param ocf: the Op-code Command (10 bits).
        :type ocf: bytes
        :returns: OgfOcf instance.
        :rtype: OgfOcf

    """
    def __init__(self,name,ogf=b"\x00",ocf=b"\x00"):
        self.name=name
        self.ogf= ogf
        self.ocf= ocf

    def encode (self):
        val=pack("<H",(ord(self.ogf) << 10) | ord(self.ocf))
        return val

    def decode(self,data):
        val = unpack("<H",data[:len(self)])[0]
        self.ogf =val>>10
        self.ocf = int(val - (self.ogf<<10)).to_bytes(1,"big")
        self.ogf = int(self.ogf).to_bytes(1,"big")
        return data[len(self):]

    def __len__(self):
        return calcsize("<H")

    def show(self,depth=0):
        print("{}Cmd Group:".format(PRINT_INDENT*depth))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.ogf))
        print("{}Cmd Code:".format(PRINT_INDENT*depth))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.ocf))

class Itself:
    """Class representing a byte array that need no manipulation.

        :param name: The name of the instance
        :type name: str
        :returns: Itself instance.
        :rtype: Itself

    """
    def __init__(self,name):
        self.name=name
        self.val=b""

    def encode(self):
        val=pack(">%ds"%len(self.val),self.val)
        return val

    def decode(self,data):
        self.val=unpack(">%ds"%len(data),data)[0]
        return b""

    def __len__(self):
        return len(self.val)

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),":".join(map(lambda b: format(b, "02x"), self.val))))

class String:
    """Class representing a string.

        :param name: The name of the instance
        :type name: str
        :returns: String instance.
        :rtype: String

    """
    def __init__(self,name):
        self.name=name
        self.val=""

    def encode(self):
        if isinstance(self.val,str):
            self.val = self.val.encode()
        val=pack(">%ds"%len(self.val),self.val)
        return val

    def decode(self,data):
        self.val=data
        return b""

    def __len__(self):
        return len(self.val)

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))


class NBytes:
    """Class representing a byte string.

        :param name: The name of the instance
        :type name: str
        :param length: The length
        :type length: int
        :returns: NBytes instance.
        :rtype: NBytes

    """
    def __init__(self,name,length=2):
        self.name=name
        self.length=length
        self.val=b""

    def encode(self):
        val=pack(">%ds"%len(self.length),self.val)
        return val

    def decode(self,data):
        self.val=unpack(">%ds"%self.length,data[:self.length])[0][::-1]
        return data[self.length:]

    def __len__(self):
        return self.length

    def show(self,depth=0):
        if self.name:
            print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),":".join(map(lambda b: format(b, "02x"), self.val))))

    def __eq__(self,b):
        return self.val==b

class NBytes_List:
    """Class representing a list of bytes string.

        :param name: The name of the instance
        :type name: str
        :param bytes: Length of the bytes strings (2, 4 or 16)
        :type bytes: int
        :returns: NBytes_List instance.
        :rtype: NBytes_List

    """
    def __init__(self,name,bytes=2):
        #Bytes should be one of 2, 4 or 16
        self.name=name
        self.length=bytes
        self.lonbytes = []

    def decode(self,data):
        while data:
            mynbyte=NBytes("",self.length)
            data=mynbyte.decode(data)
            self.lonbytes.append(mynbyte)
        return data

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        for x in self.lonbytes:
            x.show(depth+1)

    def __len__(self):
        return len(self.lonbytes)+self.length

    def __contains__(self,b):
        for x in self.lonbytes:
            if b == x:
                return True

        return False

class Float88:
    """Class representing a 8.8 fixed point quantity.

        :param name: The name of the instance
        :type name: str
        :returns: Float88 instance.
        :rtype: Float88

    """
    def __init__(self,name):
        self.name=name
        self.val=0.0

    def encode (self):
        val=pack(">h",int(self.val*256))
        return val

    def decode(self,data):
        self.val= unpack(">h",data)[0]/256.0
        return data[2:]
    def __len__(self):
        return 2

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))




class EmptyPayload:
    def __init__(self):
        pass

    def encode(self):
        return b""

    def decode(self,data):
        return data

    def __len__(self):
        return 0

    def show(self,depth=0):
        return

#
# Bluetooth starts here
#

class Packet:
    """Class representing a generic HCI packet.

        :param header: The packet header.
        :type header: bytes
        :returns: Packet instance.
        :rtype: Packet

    """
    """A generic packet that will be build fromparts"""
    def __init__(self, header="\x00", fmt=">B"):
        self.header = header
        self.fmt = fmt
        self.payload=[]
        self.raw_data=None

    def encode (self) :
        return pack(self.fmt, self.header)

    def decode (self, data):
        try:
            if unpack(self.fmt,data[:calcsize(self.fmt)])[0] == self.header:
                self.raw_data=data
                return data[calcsize(self.fmt):]
        except:
            pass
        return None

    def retrieve(self,aclass):
        """Look for a specifc class/name in the packet"""
        resu=[]
        for x in self.payload:
            try:
                if isinstance(aclass,str):
                    if x.name == aclass:
                        resu.append(x)
                else:
                    if isinstance(x,aclass):
                        resu.append(x)

                resu+=x.retrieve(aclass)
            except:
                pass
        return resu
#
# Commands
#

class HCI_Command(Packet):
    """Class representing a command HCI packet.

        :param ogf: the Op-code Group (6 bits).
        :type ogf: bytes
        :param ocf: the Op-code Command (10 bits).
        :type ocf: bytes
        :returns: HCI_Command instance.
        :rtype: HCI_Command

    """

    def __init__(self,ogf,ocf):
        super().__init__(HCI_COMMAND)
        self.cmd = OgfOcf("command",ogf,ocf)
        self.payload = []

    def encode(self):
        pld=b""
        for x in self.payload:
            pld+=x.encode()
        plen=len(pld)
        pld=b"".join([super().encode(),self.cmd.encode(),pack(">B",plen),pld])
        return pld

    def show(self,depth=0):
        self.cmd.show(depth)
        for x in self.payload:
            x.show(depth+1)

class HCI_Cmd_LE_Scan_Enable(HCI_Command):
    """Class representing a command HCI command to enable/disable BLE scanning.

        :param enable: enable/disable scanning.
        :type enable: bool
        :param filter_dups: filter duplicates.
        :type filter_dups: bool
        :returns: HCI_Cmd_LE_Scan_Enable instance.
        :rtype: HCI_Cmd_LE_Scan_Enable

    """

    def __init__(self,enable=True,filter_dups=True):
        super(self.__class__, self).__init__(b"\x08",b"\x0c")
        self.payload.append(Bool("enable",enable))
        self.payload.append(Bool("filter",filter_dups))

class HCI_Cmd_LE_Set_Scan_Params(HCI_Command):
    """Class representing an HCI command to set the scanning parameters.

    This will set a number of parameters related to the scanning functions. For the
    interval and window, it will always silently enforce the Specs that says it should be >= 2.5 ms
    and <= 10.24s. It will also silently enforce window <= interval

        :param scan_type: Type of scanning. 0 => Passive (default)
                                            1 => Active
        :type scan_type: int
        :param interval: Time in ms between the start of a scan and the next scan start. Default 10
        :type interval: int/float
        :param window: maximum advertising interval in ms. Default 10
        :type window: int.float
        :param oaddr_type: Type of own address Value 0 => public (default)
                                                     1 => Random
                                                     2 => Private with public fallback
                                                     3 => Private with random fallback
        :type oaddr_type: int
        :param filter: How white list filter is applied. 0 => No filter (Default)
                                                         1 => sender must be in white list
                                                         2 => Similar to 0. Some directed advertising may be received.
                                                         3 => Similar to 1. Some directed advertising may be received.
        :type filter: int
        :returns: HCI_Cmd_LE_Scan_Params instance.
        :rtype: HCI_Cmd_LE_Scan_Params

    """

    def __init__(self,scan_type=0x0,interval=10, window=750, oaddr_type=0,filter=0):

        super(self.__class__, self).__init__(b"\x08",b"\x0b")
        self.payload.append(EnumByte("scan type",scan_type,
                                     {0: "Passive",
                                      1: "Active"}))
        self.payload.append(UShortInt("Interval",int(round(min(10240,max(2.5,interval))/0.625)),endian="little"))
        self.payload.append(UShortInt("Window",int(round(min(10240,max(2.5,min(interval,window)))/0.625)),endian="little"))
        self.payload.append(EnumByte("own addresss type",oaddr_type,
                                     {0: "Public",
                                      1: "Random",
                                      2: "Private IRK or Public",
                                      3: "Private IRK or Random"}))
        self.payload.append(EnumByte("filter policy",filter,
                                     {0: "None",
                                      1: "Sender In White List",
                                      2: "Almost None",
                                      3: "SIWL and some"}))


class HCI_Cmd_LE_Advertise(HCI_Command):
    """Class representing a command HCI command to enable/disable BLE advertising.

        :param enable: enable/disable advertising.
        :type enable: bool
        :returns: HCI_Cmd_LE_Scan_Enable instance.
        :rtype: HCI_Cmd_LE_Scan_Enable

    """

    def __init__(self,enable=True):
        super(self.__class__, self).__init__(b"\x08",b"\x0a")
        self.payload.append(Bool("enable",enable))

class HCI_Cmd_LE_Set_Advertised_Msg(HCI_Command):
    """Class representing an HCI command to set the advertised content.

        :param enable: enable/disable advertising.
        :type enable: bool
        :returns: HCI_Cmd_LE_Scan_Enable instance.
        :rtype: HCI_Cmd_LE_Scan_Enable

    """

    def __init__(self,msg=EmptyPayload()):
        super(self.__class__, self).__init__(b"\x08",b"\x08")
        self.payload.append(msg)

class HCI_Cmd_LE_Set_Advertised_Params(HCI_Command):
    """Class representing an HCI command to set the advertised parameters.

    This will set a number of parameters relted to the advertising functions. For the
    min and max intervals, it will always silently enforce the Specs that says it should be >= 20ms
    and <= 10.24s. It will also silently enforce interval_max >= interval_min

        :param interval_min: minimum advertising interval in ms. Default 500
        :type interval_min: int/float
        :param interval_max: maximum advertising interval in ms. Default 750
        :type interval_max: int/float
        :param adv_type: Type of advertising. Value 0 +> Connectable, Scannable advertising
                                                    1 => Connectable directed advertising (High duty cycle)
                                                    2 => Scannable Undirected advertising
                                                    3 => Non connectable undirected advertising (default)
        :type adv_type: int
        :param oaddr_type: Type of own address Value 0 => public (default)
                                                     1 => Random
                                                     2 => Private with public fallback
                                                     3 => Private with random fallback
        :type oaddr_type: int
        :param paddr_type: Type of peer address Value 0 => public (default)
                                                      1 => Random
        :type paddr_type: int
        :param peer_addr: Peer MAC address Default 00:00:00:00:00:00
        :type peer_addr: str
        :param cmap: Channel map. A bit field dfined as  "Channel 37","Channel 38","Channel 39","RFU","RFU","RFU","RFU","RFU"
        Default value is 0x7. The value 0x0 is RFU.
        :type cmap: int
        :param filter: How white list filter is applied. 0 => No filter (Default)
                                                         1 => scan are filtered
                                                         2 => Connection are filtered
                                                         3 => scan and connection are filtered
        :type filter: int
        :returns: HCI_Cmd_LE_Scan_Params instance.
        :rtype: HCI_Cmd_LE_Scan_Params

    """

    def __init__(self,interval_min=500, interval_max=750,
                       adv_type=0x3, oaddr_type=0, paddr_type=0,
                       peer_addr="00:00:00:00:00:00", cmap=0x7, filter=0):

        super(self.__class__, self).__init__(b"\x08",b"\x06")
        self.payload.append(UShortInt("Adv minimum",int(round(min(10240,max(20,interval_min))/0.625)),endian="little"))
        self.payload.append(UShortInt("Adv maximum",int(round(min(10240,max(20,max(interval_min,interval_max)))/0.625)),endian="little"))
        self.payload.append(EnumByte("adv type",adv_type,
                                        {0: "ADV_IND",
                                         1: "ADV_DIRECT_IND high",
                                         2: "ADV_SCAN_IND",
                                         3: "ADV_NONCONN_IND",
                                         4: "ADV_DIRECT_IND low"}))
        self.payload.append(EnumByte("own addresss type",paddr_type,
                                     {0: "Public",
                                      1: "Random",
                                      2: "Private IRK or Public",
                                      3: "Private IRK or Random"}))
        self.payload.append(EnumByte("peer addresss type",oaddr_type,
                                     {0: "Public",
                                      1: "Random"}))
        self.payload.append(MACAddr("peer",mac=peer_addr))
        self.payload.append(BitFieldByte("Channels",cmap,["Channel 37","Channel 38","Channel 39","RFU","RFU","RFU","RFU", "RFU"]))

        self.payload.append(EnumByte("filter policy",filter,
                                     {0: "None",
                                      1: "Scan",
                                      2: "Connection",
                                      3: "Scan and Connection"}))

class HCI_Cmd_Reset(HCI_Command):
    """Class representing an HCI command to reset the adapater.


        :returns: HCI_Cmd_Reset instance.
        :rtype: HCI_Cmd_Reset

    """

    def __init__(self):
        super(self.__class__, self).__init__(b"\x03",b"\x03")


####
# HCI EVents
####

class HCI_Event(Packet):

    def __init__(self,code=0,payload=[]):
        super().__init__(HCI_EVENT)
        self.payload.append(Byte("code"))
        self.payload.append(UIntByte("length"))

    def decode(self,data):
        data=super().decode(data)
        if data is None:
            return None

        for x in self.payload:
            x.decode(data[:len(x)])
            data=data[len(x):]
        code=self.payload[0]
        length=self.payload[1].val
        if code.val==b"\x0e":
            ev = HCI_CC_Event()
            data=ev.decode(data)
            self.payload.append(ev)
        elif code.val==b"\x3e":
            ev = HCI_LE_Meta_Event()
            data=ev.decode(data)
            self.payload.append(ev)
        else:
            ev=Itself("Payload")
            data=ev.decode(data)
            self.payload.append(ev)
        return data

    def show(self,depth=0):
        print("{}HCI Event:".format(PRINT_INDENT*depth))
        for x in self.payload:
            x.show(depth+1)


class HCI_CC_Event(Packet):
    """Command Complete event"""
    def __init__(self):
        self.name="Command Completed"
        self.payload=[UIntByte("allow pkt"),OgfOcf("cmd"),Itself("resp code")]


    def decode(self,data):
        for x in self.payload:
            data=x.decode(data)
        return data

    def show(self,depth=0):
        for x in self.payload:
            x.show(depth+1)

class HCI_LE_Meta_Event(Packet):
    def __init__(self):
        self.name="LE Meta"
        self.payload=[Byte("code")]

    def decode(self,data):
        for x in self.payload:
            data=x.decode(data)
        code=self.payload[0]
        if code.val==b"\x02":
            ev=HCI_LEM_Adv_Report()
            data=ev.decode(data)
            self.payload.append(ev)
        else:
            ev=Itself("Payload")
            data=ev.decode(data)
            self.payload.append(ev)
        return data

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        for x in self.payload:
            x.show(depth+1)


class HCI_LEM_Adv_Report(Packet):
    def __init__(self):
        self.name="Adv Report"
        self.payload=[UIntByte("num reports"),
                      EnumByte("ev type",0,{0:"generic adv", 3:"no connection adv", 4:"scan rsp"}),
                      EnumByte("addr type",0,{0:"public", 1:"random"}),
                      MACAddr("peer"),UIntByte("length")]


    def decode(self,data):

        for x in self.payload:
            data=x.decode(data)
        #Now we have a sequence of len, type data with possibly a RSSI byte at the end
        while len(data) > 1:
            length=UIntByte("sublen")
            data=length.decode(data)
            code=EIR_Hdr()
            data=code.decode(data)

            if code.val == 0x01:
                #Flag
                myinfo=BitFieldByte("flags",0,["Undef","Undef","Simul LE - BR/EDR (Host)","Simul LE - BR/EDR (Control.)","BR/EDR Not Supported",
                                           "LE General Disc.","LE Limited Disc."])
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x02:
                myinfo=NBytes_List("Incomplete uuids",2)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x03:
                myinfo=NBytes_List("Complete uuids",2)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x04:
                myinfo=NBytes_List("Incomplete uuids",4)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x05:
                myinfo=NBytes_List("Complete uuids",4)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x06:
                myinfo=NBytes_List("Incomplete uuids",16)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x07:
                myinfo=NBytes_List("Complete uuids",16)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x14:
                myinfo=NBytes_List("Service Solicitation uuid",2)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x16:
                myinfo=Adv_Data("Advertised Data",2)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x1f:
                myinfo=NBytes_List("Service Solicitation uuid",4)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x20:
                myinfo=Adv_Data("Advertised Data",4)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x15:
                myinfo=NBytes_List("Service Solicitation uuid",16)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x21:
                myinfo=Adv_Data("Advertised Data",16)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x08:
                myinfo=String("Short Name")
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            elif code.val == 0x09:
                myinfo=String("Complete Name")
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)
            else:
                myinfo=Itself("Payload for %s"%code.strval)
                xx=myinfo.decode(data[:length.val-len(code)])
                self.payload.append(myinfo)

            data=data[length.val-len(code):]
        if data:
            myinfo=IntByte("rssi")
            data=myinfo.decode(data)
            self.payload.append(myinfo)
        return data

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        for x in self.payload:
            x.show(depth+1)

class EIR_Hdr(Packet):
    def __init__(self):
        self.type= EnumByte("type", 0, {
            0x01: "flags",
            0x02: "incomplete_list_16_bit_svc_uuids",
            0x03: "complete_list_16_bit_svc_uuids",
            0x04: "incomplete_list_32_bit_svc_uuids",
            0x05: "complete_list_32_bit_svc_uuids",
            0x06: "incomplete_list_128_bit_svc_uuids",
            0x07: "complete_list_128_bit_svc_uuids",
            0x08: "shortened_local_name",
            0x09: "complete_local_name",
            0x0a: "tx_power_level",
            0x0d: "class_of_device",
            0x0e: "simple_pairing_hash",
            0x0f: "simple_pairing_rand",
            0x10: "sec_mgr_tk",
            0x11: "sec_mgr_oob_flags",
            0x12: "slave_conn_intvl_range",
            0x17: "pub_target_addr",
            0x18: "rand_target_addr",
            0x19: "appearance",
            0x1a: "adv_intvl",
            0x1b: "le_addr",
            0x1c: "le_role",
            0x14: "list_16_bit_svc_sollication_uuids",
            0x1f: "list_32_bit_svc_sollication_uuids",
            0x15: "list_128_bit_svc_sollication_uuids",
            0x16: "svc_data_16_bit_uuid",
            0x20: "svc_data_32_bit_uuid",
            0x21: "svc_data_128_bit_uuid",
            0x22: "sec_conn_confirm",
            0x23: "sec_conn_rand",
            0x24: "uri",
            0xff: "mfg_specific_data",
        })

    def decode(self,data):
        return self.type.decode(data)

    def show(self):
        return self.type.show()

    @property
    def val(self):
        return self.type.val

    @property
    def strval(self):
        return self.type.strval

    def __len__(self):
        return len(self.type)

class Adv_Data(Packet):
    def __init__(self,name,length):
        self.name=name
        self.length=length
        self.payload=[]

    def decode(self,data):
        myinfo=NBytes("Service Data uuid",self.length)
        data=myinfo.decode(data)
        self.payload.append(myinfo)
        if data:
            myinfo=Itself("Adv Payload")
            data=myinfo.decode(data)
            self.payload.append(myinfo)
        return data

    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        for x in self.payload:
            x.show(depth+1)

    def __len__(self):
        resu=0
        for x in self.payload:
            resu+=len(x)
        return resu



#
# The defs are over. Now the realstuffs
#

def create_bt_socket(interface=0):
    exceptions = []
    sock = None
    try:
        sock = socket.socket(family=socket.AF_BLUETOOTH,
                             type=socket.SOCK_RAW,
                             proto=socket.BTPROTO_HCI)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, pack("IIIh2x", 0xffffffff,0xffffffff,0xffffffff,0)) #type mask, event mask, event mask, opcode
        try:
            sock.bind((interface,))
        except OSError as exc:
            exc = OSError(
                    exc.errno, 'error while attempting to bind on '
                    'interface {!r}: {}'.format(
                        interface, exc.strerror))
            exceptions.append(exc)
    except OSError as exc:
        if sock is not None:
            sock.close()
        exceptions.append(exc)
    except:
        if sock is not None:
            sock.close()
        raise
    if len(exceptions) == 1:
        raise exceptions[0]
    elif len(exceptions) > 1:
        model = str(exceptions[0])
        if all(str(exc) == model for exc in exceptions):
            raise exceptions[0]
        raise OSError('Multiple exceptions: {}'.format(
            ', '.join(str(exc) for exc in exceptions)))
    return sock

###########

class BLEScanRequester(asyncio.Protocol):
    '''Protocol handling the requests'''
    def __init__(self):
        self.transport = None
        self.smac = None
        self.sip = None
        self.process = self.default_process

    def connection_made(self, transport):
        self.transport = transport
        command=HCI_Cmd_LE_Set_Scan_Params()
        self.transport.write(command.encode())

    def connection_lost(self, exc):
        super().connection_lost(exc)

    def send_scan_request(self):
        '''Sending LE scan request'''
        command=HCI_Cmd_LE_Scan_Enable(True,False)
        self.transport.write(command.encode())

    def stop_scan_request(self):
        '''Sending LE scan request'''
        command=HCI_Cmd_LE_Scan_Enable(False,False)
        self.transport.write(command.encode())

    def send_command(self,command):
        '''Sending an arbitrary command'''
        self.transport.write(command.encode())

    def data_received(self, packet):
        self.process(packet)

    def default_process(self,data):
        pass
