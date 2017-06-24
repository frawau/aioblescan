# aioblescan

aioblescan is a Python 3/asyncio library to listen for BLE advertized packets.


# Installation

We are on PyPi so

     pip3 install aioblescan
or
     python3 -m pip install aioblescan
     


# How to use

Essentially, you create a function to process the incoming
information and you attach it to the BTScanRequester.You then crate a bluetooth
connection, you issue the scan command and wait for incoming events.

You can use EddyStone or RuuviWeather to retrieve specific information


The easiest way is to look at the __main__ file. You can run the module wuth

    python3 -m aioblescan
    
"-h" for help.
      
# FAQ

Why not use scapy?

    Scapy is great and you can do
    
        import scapy.all as sa
        test=sa.BluetoothHCISocket(0)
        command=sa.HCI_Cmd_LE_Set_Scan_Enable(enable=1,filter_dups=0)
        chdr=sa.HCI_Command_Hdr(len=len(command))
        hdr=sa.HCI_Hdr(type=1)
        test.send(hdr / chdr / command)

    to get things going. But... the great thing with Scapy is that there is some
    many versions to choose from.... and not all have all the same fuctions ... and
    installation can be haphazard, with some version not installing easely. Also
    scapy inludes a lot of other protocols and could be an overkill... lastly it
    is never too late to learn...
    
What can you track?

    aioblescan will try to parse all the incoming advertized information. You can see
    the raw data when it does not know what to do. With EddyStone beacon you can see the
    URL, Telemetry and UID
