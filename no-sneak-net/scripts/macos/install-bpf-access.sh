#!/bin/sh
# Gives the members of group access_bpf read/write on /dev/bpf*, so no-sneak's macOS layer-2
# backend (libpcap, DarwinPcapBackend) opens without root: ARP/NDP sweep, MAC addresses and
# passive observation as an ordinary user. The same mechanism as Wireshark's ChmodBPF.
#
#   sudo ./install-bpf-access.sh            # adds $SUDO_USER to the group
#   sudo ./install-bpf-access.sh <user>     # adds <user> instead
#
# Then log out and back in (group membership is read at login). Undo: uninstall-bpf-access.sh.
#
# What it changes: creates group access_bpf, installs a boot-time LaunchDaemon that re-applies
# the permissions (macOS recreates /dev/bpf* with mode 0600 at every boot), and applies them now.
# Capture stays non-promiscuous unless asked for; this grants the ability to capture on this
# machine's interfaces to the group's members, so add only the operators of this machine.
set -eu

GROUP=access_bpf
LABEL=io.xlogistx.nosneak.bpf
HELPER_DIR="/Library/Application Support/no-sneak"
HELPER="$HELPER_DIR/chmod-bpf.sh"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
WIRESHARK_PLIST=/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo $0 [user]" >&2
    exit 1
fi
if [ "$(uname -s)" != "Darwin" ]; then
    echo "This script is for macOS only." >&2
    exit 1
fi
TARGET_USER="${1:-${SUDO_USER:-}}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo "Name the user to grant: sudo $0 <user>" >&2
    exit 1
fi
id "$TARGET_USER" >/dev/null 2>&1 || { echo "No such user: $TARGET_USER" >&2; exit 1; }

if [ -f "$WIRESHARK_PLIST" ]; then
    echo "Wireshark's ChmodBPF is installed and already manages /dev/bpf* for group $GROUP."
    echo "Adding $TARGET_USER to $GROUP is all that is needed:"
    dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP"
    echo "Done. Log out and back in."
    exit 0
fi

if ! dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
    dseditgroup -o create -r "BPF device access (no-sneak)" "$GROUP"
    echo "Created group $GROUP."
fi
dseditgroup -o edit -a "$TARGET_USER" -t user "$GROUP"
echo "Added $TARGET_USER to $GROUP."

mkdir -p "$HELPER_DIR"
cat > "$HELPER" <<'EOF'
#!/bin/sh
# Installed by no-sneak's install-bpf-access.sh. macOS clones /dev/bpfN on first open; touch the
# first 256 so they exist, then hand them to group access_bpf.
i=0
while [ "$i" -lt 256 ]; do
    : < "/dev/bpf$i" 2>/dev/null || true
    i=$((i + 1))
done
chgrp access_bpf /dev/bpf*
chmod g+rw /dev/bpf*
EOF
chown root:wheel "$HELPER"
chmod 755 "$HELPER"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>$HELPER</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"

/bin/sh "$HELPER"
ls -l /dev/bpf0
echo "Done. Log out and back in, then 'hostscan status' should report FULL."
