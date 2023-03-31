# ZDAR protocol

is a joke protocol created for discovery of other ZDAR devices
this protocol runs on UDP broadcast

## How does it work?

All ZDAR devices send an announcement of themselfs every x seconds (defined by the ZDAR interval) and other ZDAR devices listen for these messages and fill the zdar DB.

When there is no ZDAR announcement received in zdar\_interval * 2 seconds, the entry is deleted
