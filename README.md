# ZDAR protocol

is a joke protocol created for discovery of other ZDAR devices
this protocol runs on UDP broadcast

## How does it work?

All ZDAR devices send an announcement of themselfs every x seconds (defined by the ZDAR interval) and other ZDAR devices listen for these messages and fill the zdar DB.

When there is no ZDAR announcement received in zdar\_interval * 2 seconds, the entry is deleted

## Output

```

    ███████╗██████╗  █████╗ ██████╗
    ╚══███╔╝██╔══██╗██╔══██╗██╔══██╗
      ███╔╝ ██║  ██║███████║██████╔╝
     ███╔╝  ██║  ██║██╔══██║██╔══██╗
    ███████╗██████╔╝██║  ██║██║  ██║
    ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

Version: 3
Local ZDAR interval: 5
Local alias: Gaming PC
Status: Listening

Discovered:

         IP address      "Alias" Hostname

         192.168.1.141   "Gaming PC" Windows-PC
         └ Last seen: 2s
         └ Version: 3
         └ ZDAR interval: 5s
         └ Platform: Windows-10-10.0.19041-SP0

         192.168.1.253   "Laptop" Lenovo-T470
         └ Last seen: 1s
         └ Version: 3
         └ ZDAR interval: 5s
         └ Platform: Linux-5.10.0-21-amd64-x86_64-with-glibc2.31    
```
