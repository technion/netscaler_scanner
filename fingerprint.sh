#!/bin/sh
# ns-remote-patchcheck.sh <host[:port]> [host2 ...]
# ---------------------------------------------------------------------------
# Remote, UNAUTHENTICATED patch-status check for NetScaler Gateway against
# CTX697096 (September 2026 8-CVE bulletin, fixed in 14.1-73.37).
#
# ORACLE
#   The web/logon surface is byte-identical between 73.33 (vulnerable) and
#   73.37 (patched). The one client-facing thing that changed is the EPA Linux
#   plugin the Gateway serves at /epa/scripts/linux/nsepa.deb -- version and
#   size both moved. This reads the SIZE of that served file. Passive: a normal
#   GET, no malformed input, never touches the vulnerable code paths.
#
# WHY v2
#   v1 used `curl -I` (HEAD). NetScaler serves the .deb on GET (200) but does
#   NOT answer HEAD with Content-Length, so v1 reported "<not served>" on a box
#   that serves it fine. This version uses a ranged GET and reads Content-Range,
#   falling back to a measured (size-capped) GET if the box ignores Range.
# ---------------------------------------------------------------------------
set -u
TIMEOUT=10
DEB=/epa/scripts/linux/nsepa.deb

# size -> verdict, from the 73.33 / 73.37 bundles. CALIBRATE against your own
# 73.37 box (ns-local-patchcheck.sh) -- the installer may post-process the
# served file so its size differs from the raw bundle size below.
verdict_for_size() {
  case "$1" in
    10688726) echo "PATCHED   (nsepa.deb 10688726 => 14.1-73.37 or later)";;
    11230664) echo "VULNERABLE(nsepa.deb 11230664 => 14.1-73.33, pre-CTX697096)";;
    ""|0)     echo "UNKNOWN   (deb not served / no size)";;
    *)        echo "UNMAPPED  (size $1 -- map it on a managed box of known build)";;
  esac
}

deb_size() {
  host="$1"
  # 1) ranged GET: ask for 1 byte, read the total from 'Content-Range: bytes 0-0/<total>'.
  hdr=$(curl -sk --max-time "$TIMEOUT" -r 0-0 -D - -o /dev/null "https://$host$DEB" 2>/dev/null)
  total=$(printf '%s' "$hdr" \
    | awk 'BEGIN{IGNORECASE=1} /^content-range:/ {n=split($0,a,"/"); v=a[n]; gsub(/[^0-9]/,"",v); print v; exit}')
  if [ -n "$total" ]; then echo "$total"; return; fi
  # 2) server ignored Range (returned 200, full body). Measure it (cap the download).
  #    --max-filesize keeps a hostile/huge response from running away; 20MB is ample.
  total=$(curl -sk --max-time 30 --max-filesize 20000000 -o /dev/null \
          -w '%{size_download}' "https://$host$DEB" 2>/dev/null)
  echo "${total:-0}"
}

check_host() {
  host="$1"
  echo "=================================================================="
  echo "host: $host"
  # sanity: is this even a NetScaler logon endpoint?
  code=$(curl -sk --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' \
         "https://$host/logon/LogonPoint/tmindex.html" 2>/dev/null)
  echo "  /logon/LogonPoint/tmindex.html -> HTTP $code"
  sz=$(deb_size "$host")
  echo "  nsepa.deb size = ${sz}"
  echo "  verdict: $(verdict_for_size "$sz")"
}

[ $# -ge 1 ] || { echo "usage: $0 <host[:port]> [host2 ...]"; exit 2; }
for h in "$@"; do check_host "$h"; done

# Notes:
#  * Size is a PROXY and a FLOOR: 10688726 means "73.37 or later", not exactly
#    73.37. Re-map whenever a new build lands.
#  * If EPA/client-download is disabled, the deb won't be served. ABSENCE IS NOT
#    "PATCHED" -- fall back to authenticated NITRO (show ns version) or ADM.
#  * Do NOT try to fingerprint these CVEs by sending oversized/malformed input.
#    They are memory-corruption bugs; that would be a DoS against the target.