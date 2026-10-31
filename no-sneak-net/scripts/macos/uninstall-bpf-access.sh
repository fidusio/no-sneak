#!/bin/sh
# Undoes install-bpf-access.sh: removes the LaunchDaemon and its helper and puts /dev/bpf* back
# to root-only (0600). The access_bpf group is kept when Wireshark's ChmodBPF still uses it.
#
#   sudo ./uninstall-bpf-access.sh
set -eu

GROUP=access_bpf
LABEL=io.xlogistx.nosneak.bpf
HELPER_DIR="/Library/Application Support/no-sneak"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
WIRESHARK_PLIST=/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo $0" >&2
    exit 1
fi

if [ -f "$PLIST" ]; then
    launchctl bootout system "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
fi
rm -f "$HELPER_DIR/chmod-bpf.sh"
rmdir "$HELPER_DIR" 2>/dev/null || true

if [ -f "$WIRESHARK_PLIST" ]; then
    echo "Wireshark's ChmodBPF is installed; leaving group $GROUP and /dev/bpf* to it."
    exit 0
fi
chgrp wheel /dev/bpf* 2>/dev/null || true
chmod 600 /dev/bpf* 2>/dev/null || true
if dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    dseditgroup -o delete "$GROUP"
fi
ls -l /dev/bpf0
echo "Done: /dev/bpf* is root-only again."
