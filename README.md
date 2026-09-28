# Tooling for Citrix Netscaler CTX697096 including CVE-2026-88771 and CVE-2026-88772

## Fingerprint

An unauthenticated version fingerprinting tool. This has only been tested with recent versions.

```
none@none-Virtual-Machine:~/netscaler$ ./fingerprint.sh  unpatched
==================================================================
host: unpatched
  /logon/LogonPoint/tmindex.html -> HTTP 200
  nsepa.deb size = 11230664
  verdict: VULNERABLE(nsepa.deb 11230664 => 14.1-73.33, pre-CTX697096)
none@none-Virtual-Machine:~/netscaler$ ./fingerprint.sh  patched
==================================================================
host: patched
  /logon/LogonPoint/tmindex.html -> HTTP 200
  nsepa.deb size = 10688726
  verdict: PATCHED   (nsepa.deb 10688726 => 14.1-73.37 or later)
```

## Config Parser

This automates the "Steps to determine if an appliance meets the CVE Preconditions". Realistically most devices will.

Copy your config with scp using nsconfig/ns.conf from the device.

```
none@none-Virtual-Machine:~/netscaler/september$ python3 ./citrix-conf-parse.py  beforepatch.conf 
Build: 14.1-73.33 < 14.1-73.37  [VULNERABLE]

CVE-2026-88771: PRECONDITION MET
    All deployments - no config precondition
CVE-2026-88772: not met
CVE-2026-88773: PRECONDITION MET
...

none@none-Virtual-Machine:~/netscaler/september$ python3 ./citrix-conf-parse.py  afterpatch.conf
Build: 14.1-73.37 >= 14.1-73.37  [FIXED]

CVE-2026-88771: fixed by build
CVE-2026-88772: fixed by build
CVE-2026-88773: fixed by build
CVE-2026-88774: fixed by build
CVE-2026-88775: fixed by build
CVE-2026-88776: fixed by build
CVE-2026-88777: fixed by build
CVE-2026-88778: fixed by build
```
