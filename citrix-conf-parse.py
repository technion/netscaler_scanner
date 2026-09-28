#!/usr/bin/env python3
"""
ctx697096_check.py - offline exposure check for Citrix bulletin CTX697096
(CVE-2026-88771 .. CVE-2026-88778).

Parses a saved NetScaler config (/nsconfig/ns.conf) or the output of
`show ns runningConfig`, determines the build, and evaluates each CVE's
published precondition. Standard library only.

Usage:
  ctx697096_check.py ns.conf
  ctx697096_check.py running.txt --tcpparam tcpparam.txt
  ctx697096_check.py ns.conf --version 14.1-73.33 --fips --json

Collect on the appliance (then copy off and analyse elsewhere):
  show ns runningConfig          > save as running.txt
  show ns tcpparam               > save as tcpparam.txt   (for CVE-2026-88778)
  show ns version                (confirms build, and FIPS/NDcPP edition)

Exit codes: 0 = fixed build, or no precondition met
            1 = vulnerable build with at least one precondition met
            2 = could not determine build

Preconditions are taken from the bulletin as published 2026-09-27. A config
match means the precondition is met, not that the appliance was exploited.
"""
import argparse
import json
import re
import shlex
import sys

# ---------------------------------------------------------------- versions
# branch -> first fixed build (major, minor)
FIXED = {
    ("14.1", False): (73, 37),
    ("13.1", False): (64, 23),
    ("14.1", True): (73, 37),   # 14.1-FIPS
    ("13.1", True): (37, 279),  # 13.1-FIPS and 13.1-NDcPP
}

# CVEs that need a config change even on a fixed build. Empty: all eight,
# including CVE-2026-88778, are treated as fixed by the build.
CONFIG_FIX = set()

TCP_VSERVER_TYPES = {
    "HTTP", "SSL", "SSL_BRIDGE", "TCP", "SSL_TCP", "FTP", "NNTP", "RTSP", "RDP",
    "DNS_TCP", "DOT", "SIP_TCP", "SIP_SSL", "DIAMETER", "SSL_DIAMETER", "MYSQL",
    "MSSQL", "ORACLE", "SMPP", "MQTT", "MQTT_TLS", "MONGO", "MONGO_TLS", "PROXY",
    "SSL_PROXY", "USER_TCP", "USER_SSL_TCP",
}


def parse_version(text):
    """'14.1-73.33' or 'NS14.1 Build 73.33' -> ('14.1', 73, 33)."""
    m = re.search(r"(\d+\.\d+)\s*(?:-|\s+Build\s+)(\d+)\.(\d+)", text, re.I)
    return (m.group(1), int(m.group(2)), int(m.group(3))) if m else None


def version_status(ver, fips):
    if ver is None:
        return "UNKNOWN", "build not found; pass --version"
    branch, a, b = ver
    fixed = FIXED.get((branch, fips))
    label = f"{branch}-{a}.{b}{' FIPS/NDcPP' if fips else ''}"
    if fixed is None:
        return "VULNERABLE", f"{label}: branch not covered by the bulletin (EOL) - treat as vulnerable"
    if (a, b) >= fixed:
        return "FIXED", f"{label} >= {branch}-{fixed[0]}.{fixed[1]}"
    return "VULNERABLE", f"{label} < {branch}-{fixed[0]}.{fixed[1]}"


# ---------------------------------------------------------------- config
def tokens(line):
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def opt(tok, name):
    """Value of -name in a token list, case-insensitive, else None."""
    low = [t.lower() for t in tok]
    key = "-" + name.lower()
    if key in low:
        i = low.index(key)
        if i + 1 < len(tok):
            return tok[i + 1]
    return None


class Config:
    def __init__(self, text):
        self.lines = [l.strip() for l in text.splitlines()]
        self.cmds = [l for l in self.lines if l and not l.startswith("#")]
        self.vservers = {}      # (kind, name) -> {"type":..., "dtls":..., "line":...}
        self.lsn = {}           # group -> {"ftp":..., "rtspalg":..., "line":...}
        self.dns64_pols = {}    # name -> line
        self.isn = None         # ENABLED / DISABLED if set in config
        self._parse()

    def _parse(self):
        for line in self.cmds:
            t = tokens(line)
            lt = [x.lower() for x in t]
            if len(t) < 3:
                continue
            verb = lt[0]

            # add/set <kind> vserver <name> [<type> ...]
            if len(t) >= 4 and lt[2] == "vserver" and verb in ("add", "set"):
                key = (lt[1], t[3])
                vs = self.vservers.setdefault(key, {"type": None, "dtls": None, "line": line})
                if verb == "add" and len(t) >= 5:
                    vs["type"] = t[4].upper()
                    vs["line"] = line
                d = opt(t, "dtls")
                if d:
                    vs["dtls"] = d.upper()

            elif lt[:3] in (["add", "lsn", "group"], ["set", "lsn", "group"]) and len(t) >= 4:
                g = self.lsn.setdefault(t[3], {"ftp": None, "rtspalg": None, "line": line})
                for k in ("ftp", "rtspalg"):
                    v = opt(t, k)
                    if v:
                        g[k] = v.upper()

            elif lt[:3] == ["add", "dns", "policy64"] and len(t) >= 4:
                self.dns64_pols[t[3]] = line

            elif lt[:3] == ["set", "ns", "tcpparam"]:
                v = opt(t, "enhancedISNGeneration")
                if v:
                    self.isn = v.upper()

    def grep(self, pattern):
        rx = re.compile(pattern, re.I)
        return [l for l in self.cmds if rx.search(l)]

    def vs(self, kinds=None, types=None):
        out = []
        for (kind, name), v in self.vservers.items():
            if kinds and kind not in kinds:
                continue
            if types and (v["type"] or "") not in types:
                continue
            out.append(v["line"])
        return out


# ---------------------------------------------------------------- checks
def check(cfg, tcpparam_text):
    r = {}

    r["CVE-2026-88771"] = (True, ["All deployments - no config precondition"])

    dtls = []
    for (kind, name), v in cfg.vservers.items():
        if kind == "vpn" and v["type"] and v["dtls"] != "OFF":
            dtls.append(v["line"] + ("" if v["dtls"] else "   <- -dtls not set, defaults ON"))
        elif v["type"] == "DTLS":
            dtls.append(v["line"])
    r["CVE-2026-88772"] = (bool(dtls), dtls)

    http = cfg.vs(kinds={"lb", "cs", "vpn", "authentication"}, types={"HTTP", "SSL"})
    r["CVE-2026-88773"] = (bool(http), http)

    # Bulletin's instructions for 88774 repeat 88773's vserver test; the stated
    # precondition is a URL-based expression, so list those too.
    url_expr = cfg.grep(r"HTTP\.REQ\.URL")
    r["CVE-2026-88774"] = (bool(http), http + [f"[URL expression] {l}" for l in url_expr])

    gw = cfg.grep(r"^add vpn vserver ") + cfg.grep(r"^add authentication vserver ")
    r["CVE-2026-88775"] = (bool(gw), gw)

    ora = cfg.grep(r"^add lb vserver .*ORACLE")
    r["CVE-2026-88776"] = (bool(ora), ora)

    h = []
    h += cfg.grep(r"^add (lb|cs) vserver \S+ FTP\b")
    h += cfg.grep(r"^add service \S+ \S+ FTP\b")
    h += cfg.grep(r"^add lb monitor \S+ FTP(-EXTENDED)?\b")
    for g, v in cfg.lsn.items():
        if v["ftp"] != "DISABLED":
            h.append(f"{v['line']}   <- lsn group {g}: FTP ALG not disabled")
        if v["rtspalg"] == "ENABLED":
            h.append(f"{v['line']}   <- lsn group {g}: RTSP ALG enabled")
    h += cfg.grep(r"^add lb vserver .* DNS .*-dns64 ENABLED")
    for name, line in cfg.dns64_pols.items():
        bound = [l for l in cfg.grep(r"^bind (lb|cs) vserver ") if name in tokens(l)]
        if bound:
            h.append(f"{line}   <- bound: {bound[0]}")
    h += cfg.grep(r"^add nat64 ")
    r["CVE-2026-88777"] = (bool(h), h)

    tcpvs = [l for (_, _), v in cfg.vservers.items()
             if (v["type"] or "") in TCP_VSERVER_TYPES for l in [v["line"]]]
    if tcpparam_text:
        m = re.search(r"Enhanced ISN Generation:\s*(\w+)", tcpparam_text, re.I)
        isn = m.group(1).upper() if m else None
        src = "tcpparam output"
    else:
        isn = cfg.isn
        src = "ns.conf" if isn else "not set in config; assumed DISABLED - confirm with show ns tcpparam"
    isn_eff = isn or "DISABLED"
    met = bool(tcpvs) and isn_eff == "DISABLED"
    r["CVE-2026-88778"] = (met, [f"Enhanced ISN Generation: {isn_eff} ({src})",
                                  f"{len(tcpvs)} TCP-type vserver(s)"] + tcpvs[:5])
    return r


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("config", help="ns.conf or saved 'show ns runningConfig' output")
    ap.add_argument("--version", help="override build, e.g. 14.1-73.33")
    ap.add_argument("--fips", action="store_true", help="appliance is FIPS / NDcPP edition")
    ap.add_argument("--tcpparam", help="saved 'show ns tcpparam' output")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    text = open(a.config, encoding="utf-8", errors="replace").read()
    tcp = open(a.tcpparam, encoding="utf-8", errors="replace").read() if a.tcpparam else None

    ver = parse_version(a.version) if a.version else None
    if ver is None:
        hdr = next((l for l in text.splitlines() if l.startswith("#NS")), "")
        ver = parse_version(hdr)
    vstat, vmsg = version_status(ver, a.fips)

    results = check(Config(text), tcp)

    if a.json:
        print(json.dumps({"version": vmsg, "version_status": vstat,
                          "cves": {k: {"precondition_met": m, "evidence": e,
                                       "fixed_by": "config" if k in CONFIG_FIX else "build"}
                                   for k, (m, e) in results.items()}}, indent=2))
    else:
        print(f"Build: {vmsg}  [{vstat}]\n")
        for cve, (met, ev) in results.items():
            config_fix = cve in CONFIG_FIX
            if vstat == "FIXED" and not config_fix:
                print(f"{cve}: fixed by build")
                continue
            if config_fix:
                verdict = "EXPOSED - needs config change, not fixed by upgrade" if met else "not met"
            else:
                verdict = "PRECONDITION MET" if met else "not met"
            print(f"{cve}: {verdict}")
            if not met:
                ev = ev[:1] if config_fix else []
            for e in ev[:10]:
                print(f"    {e}")
            if len(ev) > 10:
                print(f"    ... {len(ev) - 10} more")
        if vstat == "VULNERABLE":
            print("\nCVE-2026-88771 applies to every deployment on this build: upgrade.")

    if vstat == "UNKNOWN":
        sys.exit(2)
    build_hit = vstat == "VULNERABLE" and any(m for m, _ in results.values())
    config_hit = any(results[c][0] for c in CONFIG_FIX)
    sys.exit(1 if build_hit or config_hit else 0)


if __name__ == "__main__":
    main()