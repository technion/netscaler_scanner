#!/bin/sh
#
# NetScaler IOC scanner
#
# Runs a set of host checks for indicators of compromise tied to the
# latest NetScaler attack campaign (PHP webshells, the ".uxd" Python
# backdoor, and tampering with /bin/sh).
#
# Usage: run as root from the NetScaler shell (type "shell" at the CLI):
#     sh mandiant-scanner.sh
#
# Each check prints what it does, what a clean result looks like, the raw
# output, and a verdict. A summary is printed at the end.
#
# This script is read-only: it makes no changes to the appliance.

FINDINGS=0

header() {
    printf '\n==============================================================\n'
    printf 'CHECK %s: %s\n' "$1" "$2"
    printf '==============================================================\n'
}

explain() {
    printf '%s\n' "$@"
}

output() {
    printf '\n--- Output ---\n'
    if [ -n "$1" ]; then
        printf '%s\n' "$1"
    else
        printf '(no output)\n'
    fi
    printf -- '--------------\n'
}

clean() {
    printf '[CLEAN]   %s\n' "$1"
}

suspicious() {
    printf '[SUSPECT] %s\n' "$1"
    FINDINGS=$((FINDINGS + 1))
}

manual() {
    printf '[REVIEW]  %s\n' "$1"
}

printf 'NetScaler IOC scan - host: %s - %s\n' "$(hostname)" "$(date)"

if [ "$(id -u)" -ne 0 ]; then
    printf 'WARNING: not running as root; some checks may return incomplete results.\n'
fi


# ---------------------------------------------------------------------------
header 1 "Apache config tampering (/etc/httpd.conf)"
explain \
    "Command: grep -En -i \"application/x-httpd-php|php_flag engine on|AliasMatch\" /etc/httpd.conf" \
    "" \
    "Attackers enable PHP execution in directories that normally only serve" \
    "static files, so a dropped webshell will run. They do this by adding" \
    "'php_flag engine on', 'AliasMatch' rules, or extra PHP AddType lines." \
    "" \
    "Expected (clean): only the two stock AddType lines, e.g." \
    "    AddType application/x-httpd-php .php" \
    "    AddType application/x-httpd-php-source .phps" \
    "(line numbers vary by firmware build)." \
    "Suspicious: any 'php_flag engine on' or 'AliasMatch' line, or any" \
    "additional AddType line mapping other extensions to PHP."

OUT=$(grep -En -i "application/x-httpd-php|php_flag engine on|AliasMatch" /etc/httpd.conf 2>&1)
output "$OUT"

EXTRA=$(printf '%s\n' "$OUT" | grep -v -E 'AddType application/x-httpd-php \.php$|AddType application/x-httpd-php-source \.phps$' | grep -v '^$')
if [ -n "$EXTRA" ]; then
    suspicious "Non-default PHP/Alias directives found in /etc/httpd.conf:"
    printf '%s\n' "$EXTRA" | sed 's/^/          /'
else
    clean "Only the default PHP AddType directives are present."
fi


# ---------------------------------------------------------------------------
header 2 "Webshells in VPN client script/media directories"
explain \
    "Command: file /var/netscaler/gui/vpn/scripts/linux/* /var/netscaler/gui/vpns/scripts/vista/* \\" \
    "              /var/netscaler/gui/vpns/scripts/mac/* /netscaler/ns_gui/vpn/media/* | grep -E \"ASCII text|PHP script\"" \
    "" \
    "These directories are web-reachable and should only hold client installers," \
    "images and a couple of version files. Attackers drop PHP webshells here." \
    "'file' identifies each file's real type regardless of its extension." \
    "" \
    "Expected (clean): only the two known text files:" \
    "    /var/netscaler/gui/vpn/scripts/linux/clientversions.xml: ASCII text" \
    "    /var/netscaler/gui/vpns/scripts/mac/macversion.txt:      ASCII text" \
    "Suspicious: any file reported as 'PHP script', or any other text file."

OUT=$(file /var/netscaler/gui/vpn/scripts/linux/* \
           /var/netscaler/gui/vpns/scripts/vista/* \
           /var/netscaler/gui/vpns/scripts/mac/* \
           /netscaler/ns_gui/vpn/media/* 2>/dev/null | grep -E "ASCII text|PHP script")
output "$OUT"

EXTRA=$(printf '%s\n' "$OUT" | grep -v -E '/clientversions\.xml:|/macversion\.txt:' | grep -v '^$')
if [ -n "$EXTRA" ]; then
    suspicious "Unexpected text/PHP files found (inspect these for webshell code):"
    printf '%s\n' "$EXTRA" | sed 's/^/          /'
else
    clean "Only the known version files are present."
fi


# ---------------------------------------------------------------------------
header 3 "Backdoor lock/port files in /tmp"
explain \
    "Command: ls -la /tmp/.uxdport* /tmp/.uxdlock" \
    "" \
    "The Python backdoor used in this campaign writes hidden '.uxdport' and" \
    "'.uxdlock' files to /tmp to track its listening port and prevent" \
    "duplicate instances." \
    "" \
    "Expected (clean): 'No such file or directory' for both." \
    "Suspicious: either file exists."

OUT=$(ls -la /tmp/.uxdport* /tmp/.uxdlock 2>&1)
output "$OUT"

FOUND=""
for f in /tmp/.uxdport* /tmp/.uxdlock; do
    [ -e "$f" ] && FOUND="$FOUND $f"
done
if [ -n "$FOUND" ]; then
    suspicious "Backdoor artefacts present:$FOUND"
else
    clean "No .uxdport / .uxdlock files in /tmp."
fi


# ---------------------------------------------------------------------------
header 4 "/bin/sh permissions and ownership"
explain \
    "Command: ls -l /bin/sh" \
    "" \
    "Attackers may set the setuid bit on /bin/sh (or replace it) so any" \
    "low-privileged foothold can spawn a root shell." \
    "" \
    "Expected (clean): '-r-xr-xr-x  1 root  wheel ... /bin/sh'" \
    "Suspicious: an 's' in the permissions (e.g. -r-sr-xr-x), an owner other" \
    "than root, or a modification date that doesn't match your last firmware" \
    "upgrade. Compare the size against another NetScaler on the same build."

OUT=$(ls -l /bin/sh 2>&1)
output "$OUT"

PERMS=$(printf '%s' "$OUT" | awk '{print $1}')
OWNER=$(printf '%s' "$OUT" | awk '{print $3}')
if printf '%s' "$PERMS" | grep -q '[sS]'; then
    suspicious "/bin/sh has the setuid/setgid bit set ($PERMS)."
elif [ "$OWNER" != "root" ]; then
    suspicious "/bin/sh is owned by '$OWNER', not root."
elif [ "$PERMS" != "-r-xr-xr-x" ]; then
    suspicious "/bin/sh has non-default permissions ($PERMS)."
else
    clean "Permissions and owner are default."
fi
manual "Confirm the size and date above match a known-good appliance on the same firmware."


# ---------------------------------------------------------------------------
header 5 "Running Python backdoor processes"
explain \
    "Command: ps aux | grep -E \"python.*(\\.uxd|uxdport|uxdlock|base64)\"" \
    "" \
    "Looks for a running Python process referencing the .uxd files or" \
    "decoding a base64 payload - the in-memory form of the backdoor." \
    "" \
    "Expected (clean): no matching processes. (When run by hand you will see" \
    "the grep command itself in the output - that is normal and is filtered" \
    "out here.)" \
    "Suspicious: any python process matching the pattern."

OUT=$(ps auxww | grep -E "python.*(\.uxd|uxdport|uxdlock|base64)" | grep -v grep)
output "$OUT"

if [ -n "$OUT" ]; then
    suspicious "Python process(es) matching backdoor pattern are running."
else
    clean "No matching Python processes."
fi


# ---------------------------------------------------------------------------
printf '\n==============================================================\n'
printf 'SUMMARY\n'
printf '==============================================================\n'
if [ "$FINDINGS" -eq 0 ]; then
    printf 'No indicators of compromise found (%s). Review any [REVIEW] items above.\n' "$(hostname)"
    exit 0
else
    printf '%s suspicious finding(s) on %s. Treat the appliance as potentially\n' "$FINDINGS" "$(hostname)"
    printf 'compromised: preserve evidence (do not reboot) and escalate to IR.\n'
    exit 1
fi
