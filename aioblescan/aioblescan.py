#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is simply a python only Bluetooth LE Scan command with
# decoding of advertised packets
# 
# Copyright (c) 2017 François Wautier
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
from base64 import b64decode


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

#
# Let's define some useful types
#
class MACAddr:
    def __init__(self,name,mac="00:00:00:00:00:00"):
        self.name = name
        self.val=mac
        
    def encode (self):
        return int(self.val.replace(":",""),16).to_bytes(6,"little")
    
    def decode(self,data):
        self.val=':'.join(a + b for a, b in list(zip(*[iter(data[:6].hex())]*2))[::-1])
        return data[6:]
    
    def __len__(self):
        return 6
    
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class Bool:
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
    def __init__(self,name,val=0):
        self.name=name
        self.val=val
        
    def encode (self):
        val=pack(">c",self.val)
        return val
    
    def decode(self,data):
        self.val= unpack(">c",data[:1])[0]
        return data[1:]
        
    def __len__(self):
        return 1
   
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),":".join(map(lambda b: format(b, "02x"), self.val))))
    
class EnumByte:
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
    def __init__(self,name,val=0):
        self.name=name
        self.val=val
        
    def encode (self):
        val=pack(">h",self.val)
        return val
    
    def decode(self,data):
        self.val= unpack(">h",data[:2])[0]
        return data[2:]
        
    def __len__(self):
        return 2
    
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))
   
class UShortInt:
    def __init__(self,name,val=0):
        self.name=name
        self.val=val
        
    def encode (self):
        val=pack(">H",self.val)
        return val
    
    def decode(self,data):
        self.val= unpack(">H",data[:2])[0]
        return data[2:]
        
    def __len__(self):
        return 2 
    
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))
        
class LongInt:
    def __init__(self,name,val=0):
        self.name=name
        self.val=val
        
    def encode (self):
        val=pack(">l",self.val)
        return val
    
    def decode(self,data):
        self.val= unpack(">l",data[:4])[0]
        return data[4:]
        
    def __len__(self):
        return 4
    
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))
   
class ULongInt:
    def __init__(self,name,val=0):
        self.name=name
        self.val=val
        
    def encode (self):
        val=pack(">L",self.val)
        return val
    
    def decode(self,data):
        self.val= unpack(">L",data[:4])[0]
        return data[4:]
        
    def __len__(self):
        return 4 
    
    def show(self,depth=0):
        print("{}{}:".format(PRINT_INDENT*depth,self.name))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.val))

class OgfOcf:
    def __init__(self,name,ogf=b"\x00",ocf=b"\x00"):
        self.name=name
        self.ogf= ogf 
        self.ocf= ocf
        
    def encode (self):
        val=pack("<H",(ord(self.ogf) << 10) | ord(self.ocf))
        return val
    
    def decode(self,data):
        val = unpack(">H",data[:len(self)])[0]
        self.ogf =val>>10
        self.ocf = int(val - (self.ogf<<10)).to_bytes(1,"big")
        self.ogf = int(self.ogf).to_bytes(1,"big")
        return data[len(self):]
        
    def __len__(self):
        return calcsize(">H")
    
    def show(self,depth=0):
        print("{}Cmd Group:".format(PRINT_INDENT*depth))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.ogf))
        print("{}Cmd Code:".format(PRINT_INDENT*depth))
        print("{}{}".format(PRINT_INDENT*(depth+1),self.ocf))
    
class Itself:
    """Idempotent"""
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
    """Idempotent"""
    def __init__(self,name):
        self.name=name
        self.val=""
        
    def encode(self):
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
    """Idempotent"""
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
    """8.8 fixed point quantity"""
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
    """A generic packet that will be build fromparts"""
    def __init__(self, header="\x00", fmt=">B"):
        self.header = header
        self.fmt = fmt
        self.payload=[]
        
    def encode (self) :
        return pack(self.fmt, self.header)
        
    def decode (self, data):
        try:
            if unpack(self.fmt,data[:calcsize(self.fmt)])[0] == self.header:
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
    
    def __init__(self,enable=True,filter_dups=True):
        super(self.__class__, self).__init__(b"\x08",b"\x0c")
        self.payload.append(Bool("enable",enable))
        self.payload.append(Bool("filter",filter_dups))
        
####
# HCI EVents
####

class HCI_Event(Packet):
    
    def __init__(self,code=0,payload=[]):
        super().__init__(HCI_EVENT)
        self.payload.append(Byte("code"))
        self.payload.append(UIntByte("length"))
        
    def decode(self,data):
        try:
            if unpack(self.fmt,data[:calcsize(self.fmt)])[0] == self.header:
                data=data[calcsize(self.fmt):]
        except:
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
        print("{}{}:".format(PRINT_INDENT*depth),self.name)
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
            myinfo=IntByte("RSSI")
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
            0x22: "sec_conn_rand",
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
# A few convenience functions
#

def EddyStone(packet):
    """Check a parsed packet and figure out if it is an Eddystone Beacon.
    If it is , return the relevant data as a dictionary.
    
    Return None, it is not an Eddystone Beacon advertising packet"""
    
    ssu=packet.retrieve("Complete uuids")
    found=False
    for x in ssu:
        if EDDY_UUID in x:
            found=True
            break
    if not found:
        return None
    
    found=False
    adv=packet.retrieve("Advertised Data")
    for x in adv:
        luuid=x.retrieve("Service Data uuid")
        for uuid in luuid:
            if EDDY_UUID == uuid:
                found=x
                break
        if found:
            break
       

    if not found:
        return None
    
    try:
        top=found.retrieve("Adv Payload")[0]
    except:
        return None
    #Rebuild that part of the structure
    found.payload.remove(top)
    #Now decode
    result={}
    data=top.val
    etype=EnumByte("type",0,{0x00:"Eddystone-UID",0x10:"Eddystone-URL",0x20:"Eddystone-TLM",0x30:"Eddystone-EID"})
    data=etype.decode(data)
    found.payload.append(etype)
    if etype.val== 0x00:
        power=IntByte("power")
        data=power.decode(data[:len(power)])
        found.payload.append(power)
        result["power"]=power.val
        
        nspace=Itself("namespace")
        xx=nspace.decode(data[:10])  #According to https://github.com/google/eddystone/tree/master/eddystone-uid
        data=data[10:]
        found.payload.append(nspace)
        result["name space"]=nspace.val
                 
        nspace=Itself("instance")
        xx=nspace.decode(data[:6])  #According to https://github.com/google/eddystone/tree/master/eddystone-uid
        data=data[6:]
        found.payload.append(nspace)
        result["instance"]=nspace.val
        
    elif etype.val== 0x10:
        power=IntByte("power")
        data=power.decode(data)
        found.payload.append(power)
        result["power"]=power.val
        
        url=EnumByte("type",0,{0x00:"http://www.",0x01:"https://www.",0x02:"http://",0x03:"https://"})
        data=url.decode(data)
        result["url"]=url.strval
        for x in data:
            if x == b"\x00":
                result["url"]+=".com/"
            elif x == b"\x01":
                result["url"]+=".org/"
            elif x == b"\x02":
                result["url"]+=".edu/"
            elif x == b"\x03":
                result["url"]+=".net/"
            elif x == b"\x04":
                result["url"]+=".info/"
            elif x == b"\x05":
                result["url"]+=".biz/"
            elif x == b"\x06":
                result["url"]+=".gov/"
            elif x == b"\x07":
                result["url"]+=".com"
            elif x == b"\x08":
                result["url"]+=".org"
            elif x == b"\x09":
                result["url"]+=".edu"
            elif x == b"\x10":
                result["url"]+=".net"
            elif x == b"\x11":
                result["url"]+=".info"
            elif x == b"\x12":
                result["url"]+=".biz"
            elif x == b"\x13":
                result["url"]+=".gov"
            else:
                result["url"]+=chr(x) #x.decode("ascii") #Yep ASCII only
        url=String("url")
        url.decode(result["url"])
        found.payload.append(url)
    elif etype.val== 0x20:
        myinfo=IntByte("version")
        data=myinfo.decode(data)
        found.payload.append(myinfo)
        myinfo=ShortInt("battery")
        data=myinfo.decode(data)
        result["battery"]=myinfo.val
        found.payload.append(myinfo)
        myinfo=Float88("temperature")
        data=myinfo.decode(data)
        found.payload.append(myinfo)
        result["temperature"]=myinfo.val
        myinfo=LongInt("pdu count")
        data=myinfo.decode(data)
        found.payload.append(myinfo)
        result["pdu count"]=myinfo.val
        myinfo=LongInt("uptime")
        data=myinfo.decode(data)
        found.payload.append(myinfo)
        result["uptime"]=myinfo.val*100 #in msecs
        return result
    #elif etype.val== 0x30:
    else:
        result["data"]=data
        xx=Itself("data")
        xx.decode(data)
        found.payload.append(xx)
    return result
        
##
# Ruuvi tag stuffs
def RuuviWeather(packet):
    #Look for Ruuvi tag URL and decode it
    result={}
    url=EddyStone(packet)
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
                result["accel-x"]=int.from_bytes(val[6:8],"big",signed=True)
                result["accel-y"]=int.from_bytes(val[8:10],"big",signed=True)
                result["accel-z"]=int.from_bytes(val[10:12],"big",signed=True)
                result["voltage"]=int.from_bytes(val[12:14],"big")
                return result
        
        else:
            return None
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
            result["accel-x"]=int.from_bytes(val[6:8],"big",signed=True)
            result["accel-y"]=int.from_bytes(val[8:10],"big",signed=True)
            result["accel-z"]=int.from_bytes(val[10:12],"big",signed=True)
            result["voltage"]=int.from_bytes(val[12:14],"big")
            return result
    return None
            
            
        
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
            
    def connection_lost(self, exc):
        super().connection_lost(exc)
        
        
    def send_scan_request(self):
        '''Sending LE scan request'''
        command=HCI_Cmd_LE_Scan_Enable(True,False)
        self.transport.write(command.encode())
        
    def stop_scan_request(self):
        '''Sending LE scan request'''
        command=HCI_Cmd_LE_Scan_Enable(False,False)
        command=HCI_Cmd_LE_Scan_Enable(False,False)
        print("Sending {}".format(command.encode()))
        self.transport.write(command.encode())
        
    def data_received(self, packet):
        self.process(packet)
    
    def default_process(self,data):
        pass




