# af-conn
Hub connectivity (wifi, connmgr,  WAN LTE) daemons


Note:
This repository replaces KibanLabsInc/connectivity repository.

Fixed in Release 1.3 of	BBGW and in Release 1.2	of SAMA5

Fixed in this release:
After profile OTA, subsequent OTA's were failing.
Whitelist contained stale entries that needed to be removed.
Factory Reset event added to afEdge.
Factory	Reset event added to afLib4.
Hub logs filled up /etc	which caused profile OTA to fail.
