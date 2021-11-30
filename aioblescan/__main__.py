#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This application is an example on how to use aioblescan
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
import sys
import asyncio
import argparse
import re
import aioblescan as aiobs
from aioblescan.plugins import EddyStone
from aioblescan.plugins import RuuviWeather
from aioblescan.plugins import ATCMiThermometer
from aioblescan.plugins import ThermoBeacon

# global
opts = None


def check_mac(val):
    try:
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", val.lower()):
            return val.lower()
    except:
        pass
    raise argparse.ArgumentTypeError("%s is not a MAC address" % val)


def my_process(data):
    global opts

    ev = aiobs.HCI_Event()
    xx = ev.decode(data)
    if opts.mac:
        goon = False
        mac = ev.retrieve("peer")
        for x in mac:
            if x.val in opts.mac:
                goon = True
                break
        if not goon:
            return

    if opts.raw:
        print("Raw data: {}".format(ev.raw_data))
    noopt = True
    if opts.eddy:
        noopt = False
        xx = EddyStone().decode(ev)
        if xx:
            print("Google Beacon {}".format(xx))
            return
    if opts.ruuvi:
        noopt = False
        xx = RuuviWeather().decode(ev)
        if xx:
            print("Weather info {}".format(xx))
            return
    if opts.atcmi:
        noopt = False
        xx = ATCMiThermometer().decode(ev)
        if xx:
            print("Temperature info {}".format(xx))
            return
    if opts.thermobeacon:
        noopt = False
        xx = ThermoBeacon().decode(ev)
        if xx:
            print("Temperature info {}".format(xx))
            return
    if noopt:
        ev.show(0)


def main(args=None):
    global opts

    parser = argparse.ArgumentParser(description="Track BLE advertised packets")
    parser.add_argument(
        "-e",
        "--eddy",
        action="store_true",
        default=False,
        help="Look specificaly for Eddystone messages.",
    )
    parser.add_argument(
        "-m",
        "--mac",
        type=check_mac,
        action="append",
        help="Look for these MAC addresses.",
    )
    parser.add_argument(
        "-r",
        "--ruuvi",
        action="store_true",
        default=False,
        help="Look only for Ruuvi tag Weather station messages",
    )
    parser.add_argument(
        "-A",
        "--atcmi",
        action="store_true",
        default=False,
        help="Look only for ATC_MiThermometer tag messages",
    )
    parser.add_argument(
        "-T",
        "--thermobeacon",
        action="store_true",
        default=False,
        help="Look only for ThermoBeacon messages",
    )
    parser.add_argument(
        "-R",
        "--raw",
        action="store_true",
        default=False,
        help="Also show the raw data.",
    )
    parser.add_argument(
        "-a",
        "--advertise",
        type=int,
        default=0,
        help="Broadcast like an EddyStone Beacon. Set the interval between packet in millisec",
    )
    parser.add_argument(
        "-u",
        "--url",
        type=str,
        default="",
        help="When broadcasting like an EddyStone Beacon, set the url.",
    )
    parser.add_argument(
        "-t",
        "--txpower",
        type=int,
        default=0,
        help="When broadcasting like an EddyStone Beacon, set the Tx power",
    )
    parser.add_argument(
        "-D",
        "--device",
        type=int,
        default=0,
        help="Select the hciX device to use (default 0, i.e. hci0).",
    )
    try:
        opts = parser.parse_args()
    except Exception as e:
        parser.error("Error: " + str(e))
        sys.exit()

    event_loop = asyncio.get_event_loop()

    # First create and configure a raw socket
    mysocket = aiobs.create_bt_socket(opts.device)

    # create a connection with the raw socket
    # This used to work but now requires a STREAM socket.
    # fac=event_loop.create_connection(aiobs.BLEScanRequester,sock=mysocket)
    # Thanks to martensjacobs for this fix
    fac = event_loop._create_connection_transport(
        mysocket, aiobs.BLEScanRequester, None, None
    )
    # Start it
    conn, btctrl = event_loop.run_until_complete(fac)
    # Attach your processing
    btctrl.process = my_process
    if opts.advertise:
        command = aiobs.HCI_Cmd_LE_Advertise(enable=False)
        event_loop.run_until_complete(btctrl.send_command(command))
        command = aiobs.HCI_Cmd_LE_Set_Advertised_Params(
            interval_min=opts.advertise, interval_max=opts.advertise
        )
        event_loop.run_until_complete(btctrl.send_command(command))
        if opts.url:
            myeddy = EddyStone(param=opts.url)
        else:
            myeddy = EddyStone()
        if opts.txpower:
            myeddy.power = opts.txpower
        command = aiobs.HCI_Cmd_LE_Set_Advertised_Msg(msg=myeddy)
        event_loop.run_until_complete(btctrl.send_command(command))
        command = aiobs.HCI_Cmd_LE_Advertise(enable=True)
        event_loop.run_until_complete(btctrl.send_command(command))

    # Probe
    event_loop.run_until_complete(btctrl.send_scan_request())
    try:
        # event_loop.run_until_complete(coro)
        event_loop.run_forever()
    except KeyboardInterrupt:
        print("keyboard interrupt")
    finally:
        print("closing event loop")
        event_loop.run_until_complete(btctrl.stop_scan_request())
        command = aiobs.HCI_Cmd_LE_Advertise(enable=False)
        event_loop.run_until_complete(btctrl.send_command(command))
        conn.close()
        event_loop.close()


if __name__ == "__main__":
    main()
