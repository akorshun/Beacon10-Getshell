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
