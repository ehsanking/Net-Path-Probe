#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_tunnel.py  —  لایه ۳: انتقال داده از طریق کوئری‌های DNS

وقتی همه پورت‌ها بسته‌اند اما DNS (پورت ۵۳) باز است،
می‌توان داده را داخل کوئری‌های DNS رمزگذاری و منتقل کرد.

نحوه کار:
  client → data را base32 می‌کند → به عنوان subdomain می‌فرستد
          → e.g.  MFRA.OBQXE.yourdomain.com TXT?
  server ← داده را decode می‌کند ← پاسخ را در TXT record می‌گذارد

استفاده:
  سرور مقصد:  python3 dns_tunnel.py --server --domain yourdomain.com
  کلاینت:     python3 dns_tunnel.py --client --dns-server SERVER_IP --domain yourdomain.com
"""

import base64
import hashlib
import json
import os
import select
import socket
import struct
import sys
import threading
import time
from typing import Optional, Tuple

DOMAIN        = "t.example.com"   # دامنه‌ای که کنترل می‌کنید
MAX_CHUNK     = 30                 # حداکثر بایت در هر کوئری DNS (محدودیت label)
SESSION_TTL   = 120                # ثانیه — timeout نشست


# ─────────────────────────────────────────────────────────────
# رمزگذاری / رمزگشایی
# base32 چون در DNS label حروف کوچک/بزرگ و - مجاز است
# ─────────────────────────────────────────────────────────────
def encode_chunk(data: bytes) -> str:
    """بایت‌ها → رشته base32 (بدون padding)."""
    return base64.b32encode(data).decode().rstrip("=").lower()


def decode_chunk(label: str) -> bytes:
    """رشته base32 → بایت‌ها."""
    label = label.upper()
    pad   = (8 - len(label) % 8) % 8
    return base64.b32decode(label + "=" * pad)


# ─────────────────────────────────────────────────────────────
# ساختار پیام تانل
# ─────────────────────────────────────────────────────────────
def make_query_label(session_id: str, seq: int, data_chunk: bytes) -> str:
    """
    یک label DNS می‌سازد:
      <session_id_4chars>-<seq_hex4>-<data_b32>.<domain>
    مثال: ab12-001f-mfra.t.example.com
    """
    chunk_enc = encode_chunk(data_chunk)
    return f"{session_id[:4]}-{seq:04x}-{chunk_enc}.{DOMAIN}"


def parse_query_label(fqdn: str) -> Optional[Tuple[str, int, bytes]]:
    """label را parse می‌کند و (session_id, seq, data) برمی‌گرداند."""
    try:
        label = fqdn.split(".")[0]          # e.g. "ab12-001f-mfra"
        parts = label.split("-", 2)
        if len(parts) != 3:
            return None
        session_id, seq_hex, chunk_enc = parts
        seq  = int(seq_hex, 16)
        data = decode_chunk(chunk_enc)
        return session_id, seq, data
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────
# DNS wire-format (ساده‌شده)
# ─────────────────────────────────────────────────────────────
def build_dns_query(fqdn: str, txid: int = 0) -> bytes:
    """یک کوئری DNS TXT ساده می‌سازد."""
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    parts  = fqdn.rstrip(".").split(".")
    qname  = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    qtype  = struct.pack("!HH", 16, 1)   # TXT, IN
    return header + qname + qtype


def parse_dns_response(data: bytes) -> Optional[str]:
    """TXT record را از پاسخ DNS استخراج می‌کند."""
    try:
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None
        # رد کردن سؤال
        pos = 12
        while data[pos]:
            pos += data[pos] + 1
        pos += 5   # null byte + qtype + qclass
        # اولین answer
        pos += 2   # name pointer یا label
        if data[pos] == 0xC0:
            pos += 2
        rtype = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 8   # type + class + ttl
        rdlength = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        if rtype == 16:   # TXT
            txt_len = data[pos]
            return data[pos+1:pos+1+txt_len].decode(errors="ignore")
        return None
    except Exception:
        return None


def build_dns_txt_response(query: bytes, txt_data: str, ttl: int = 1) -> bytes:
    """پاسخ DNS با TXT record می‌سازد."""
    txid = query[:2]
    flags = b"\x81\x80"   # QR=1, AA=0, RCODE=0
    # سؤال را از query کپی می‌کنیم
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", 1)
    header  = txid + flags + qdcount + ancount + b"\x00\x00\x00\x00"
    # بخش question (کپی از query)
    question = query[12:]
    # پاسخ: pointer به question + type TXT + class IN + TTL + rdata
    txt_bytes = txt_data.encode()[:255]
    rdata     = bytes([len(txt_bytes)]) + txt_bytes
    answer    = (
        b"\xc0\x0c"                          # pointer به question name
        + struct.pack("!HHI", 16, 1, ttl)    # TXT, IN, TTL
        + struct.pack("!H", len(rdata))
        + rdata
    )
    return header + question + answer


# ─────────────────────────────────────────────────────────────
# سرور DNS تانل (سمت مقصد)
# ─────────────────────────────────────────────────────────────
class DnsTunnelServer:
    """
    روی پورت UDP 53 گوش می‌دهد.
    کوئری‌های تانل را decode می‌کند، داده را جمع می‌کند،
    و پاسخ را در TXT record می‌فرستد.
    نیاز به دسترسی root یا CAP_NET_BIND_SERVICE دارد.
    """

    def __init__(self, bind_ip: str = "0.0.0.0", port: int = 5353, domain: str = DOMAIN):
        self.bind_ip  = bind_ip
        self.port     = port
        self.domain   = domain
        self.sessions: dict = {}   # session_id → {"chunks": {}, "last": float}
        self.lock     = threading.Lock()

    def _clean_sessions(self):
        now = time.monotonic()
        with self.lock:
            dead = [sid for sid, s in self.sessions.items()
                    if now - s["last"] > SESSION_TTL]
            for sid in dead:
                del self.sessions[sid]

    def _handle_chunk(self, session_id: str, seq: int, chunk: bytes) -> str:
        with self.lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = {"chunks": {}, "last": time.monotonic()}
            s = self.sessions[session_id]
            s["chunks"][seq] = chunk
            s["last"] = time.monotonic()
            # بررسی اینکه آیا پیام کامل است
            # seq=0 یعنی تنها chunk یا آخرین chunk
            if seq == 0xFFFF or len(chunk) < MAX_CHUNK:
                ordered = b"".join(s["chunks"][k] for k in sorted(s["chunks"]))
                del self.sessions[session_id]
                received = ordered.decode(errors="ignore")
                print(f"[DNS-SRV] session={session_id} data={received!r}")
                # پردازش و پاسخ
                try:
                    req = json.loads(received)
                    resp = json.dumps({"ok": True, "echo": req.get("msg", ""), "ts": int(time.time())})
                except Exception:
                    resp = json.dumps({"ok": True, "echo": received[:100]})
                return encode_chunk(resp.encode()[:200])
        return "ok"

    def serve(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.bind_ip, self.port))
        except PermissionError:
            print(f"[DNS-SRV] خطا: برای bind به پورت {self.port} نیاز به root دارید")
            print(f"[DNS-SRV] پیشنهاد: sudo python3 dns_tunnel.py --server")
            print(f"          یا: sudo setcap cap_net_bind_service=+ep $(which python3)")
            return
        print(f"[DNS-SRV] گوش می‌دهد روی {self.bind_ip}:{self.port} دامنه={self.domain}")
        cleaner = threading.Thread(target=self._cleaner_loop, daemon=True)
        cleaner.start()
        while True:
            try:
                ready = select.select([sock], [], [], 1.0)
                if not ready[0]:
                    continue
                data, addr = sock.recvfrom(512)
                threading.Thread(
                    target=self._process,
                    args=(sock, data, addr),
                    daemon=True,
                ).start()
            except KeyboardInterrupt:
                break
        sock.close()

    def _cleaner_loop(self):
        while True:
            time.sleep(30)
            self._clean_sessions()

    def _process(self, sock: socket.socket, query: bytes, addr):
        # استخراج FQDN از کوئری
        try:
            pos, labels = 12, []
            while query[pos]:
                length = query[pos]; pos += 1
                labels.append(query[pos:pos+length].decode(errors="ignore"))
                pos += length
            fqdn = ".".join(labels)
        except Exception:
            return
        parsed = parse_query_label(fqdn)
        if parsed is None:
            return
        session_id, seq, chunk = parsed
        txt_val  = self._handle_chunk(session_id, seq, chunk)
        response = build_dns_txt_response(query, txt_val)
        try:
            sock.sendto(response, addr)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# کلاینت DNS تانل (سمت مبدا)
# ─────────────────────────────────────────────────────────────
class DnsTunnelClient:
    """
    داده را به chunks تقسیم می‌کند،
    هر chunk را در یک کوئری DNS TXT می‌فرستد،
    و پاسخ را جمع‌آوری می‌کند.
    """

    def __init__(self, dns_server: str, port: int = 5353, domain: str = DOMAIN):
        self.dns_server = dns_server
        self.port       = port
        self.domain     = domain

    def _new_session_id(self) -> str:
        return hashlib.sha256(os.urandom(8)).hexdigest()[:4]

    def send(self, message: str, timeout: float = 10.0) -> Optional[str]:
        """
        یک پیام می‌فرستد و پاسخ را برمی‌گرداند.
        """
        data       = message.encode()
        chunks     = [data[i:i+MAX_CHUNK] for i in range(0, len(data), MAX_CHUNK)]
        session_id = self._new_session_id()
        sock       = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        last_response = None

        for idx, chunk in enumerate(chunks):
            seq  = idx if idx < len(chunks) - 1 else 0xFFFF
            fqdn = make_query_label(session_id, seq, chunk)
            qry  = build_dns_query(fqdn, txid=idx)
            try:
                sock.sendto(qry, (self.dns_server, self.port))
                resp_data, _ = sock.recvfrom(512)
                txt = parse_dns_response(resp_data)
                if txt:
                    try:
                        last_response = decode_chunk(txt).decode(errors="ignore")
                    except Exception:
                        last_response = txt
            except socket.timeout:
                print(f"[DNS-CLT] timeout روی chunk {idx}")
            time.sleep(0.05)   # فاصله کوتاه بین کوئری‌ها

        sock.close()
        return last_response

    def interactive(self):
        print(f"[DNS-CLT] متصل به {self.dns_server}:{self.port}  دامنه={self.domain}")
        print("پیام خود را بنویسید (exit برای خروج):")
        while True:
            try:
                msg = input("> ").strip()
                if msg.lower() in ("exit", "quit"):
                    break
                if not msg:
                    continue
                payload = json.dumps({"msg": msg, "ts": int(time.time())})
                resp    = self.send(payload)
                if resp:
                    print(f"< {resp}")
                else:
                    print("< [بدون پاسخ]")
            except KeyboardInterrupt:
                break


# ─────────────────────────────────────────────────────────────
# DoH relay — ارسال از طریق DNS over HTTPS (پورت ۴۴۳)
# وقتی پورت ۵۳ هم فیلتر است
# ─────────────────────────────────────────────────────────────
DOH_ENDPOINTS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://doh.cleanbrowsing.org/doh/family-filter/",
]

def doh_query_txt(fqdn: str, endpoint: str = DOH_ENDPOINTS[0]) -> Optional[str]:
    """
    یک کوئری TXT از طریق DoH می‌فرستد.
    پورت ۴۴۳ HTTPS — معمولاً باز است.
    """
    import urllib.request
    url = f"{endpoint}?name={fqdn}&type=TXT"
    req = urllib.request.Request(url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "curl/7.88.1",
    })
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
            body = json.loads(resp.read())
            for ans in body.get("Answer", []):
                if ans.get("type") == 16:   # TXT
                    return ans.get("data", "").strip('"')
    except Exception:
        pass
    return None


class DoHTunnelClient:
    """
    مثل DnsTunnelClient اما از طریق HTTPS DoH عبور می‌کند.
    برای زمانی که پورت ۵۳ UDP هم فیلتر است.
    """

    def __init__(self, domain: str = DOMAIN, endpoint: str = DOH_ENDPOINTS[0]):
        self.domain   = domain
        self.endpoint = endpoint

    def send_chunk(self, session_id: str, seq: int, chunk: bytes) -> Optional[str]:
        fqdn = make_query_label(session_id, seq, chunk)
        for ep in DOH_ENDPOINTS:
            result = doh_query_txt(fqdn, ep)
            if result:
                return result
        return None

    def send(self, message: str) -> Optional[str]:
        data       = message.encode()
        chunks     = [data[i:i+MAX_CHUNK] for i in range(0, len(data), MAX_CHUNK)]
        session_id = hashlib.sha256(os.urandom(8)).hexdigest()[:4]
        last       = None
        for idx, chunk in enumerate(chunks):
            seq  = idx if idx < len(chunks) - 1 else 0xFFFF
            resp = self.send_chunk(session_id, seq, chunk)
            if resp:
                try:
                    last = decode_chunk(resp).decode(errors="ignore")
                except Exception:
                    last = resp
        return last


# ─────────────────────────────────────────────────────────────
# رابط خط فرمان
# ─────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="تانل داده از طریق DNS")
    p.add_argument("--server",     action="store_true", help="اجرا به عنوان سرور (نیاز به root)")
    p.add_argument("--client",     action="store_true", help="اجرا به عنوان کلاینت")
    p.add_argument("--doh-client", action="store_true", help="کلاینت DoH (HTTPS، پورت ۴۴۳)")
    p.add_argument("--dns-server", default="127.0.0.1", help="IP سرور DNS")
    p.add_argument("--port",       type=int, default=5353, help="پورت DNS")
    p.add_argument("--domain",     default=DOMAIN,      help="دامنه کنترل‌شده")
    p.add_argument("--send",       default="",          help="ارسال یک پیام و خروج")
    args = p.parse_args()

    if args.server:
        srv = DnsTunnelServer(port=args.port, domain=args.domain)
        srv.serve()
        return 0

    if args.client:
        clt = DnsTunnelClient(args.dns_server, args.port, args.domain)
        if args.send:
            resp = clt.send(args.send)
            print(f"پاسخ: {resp}")
        else:
            clt.interactive()
        return 0

    if args.doh_client:
        clt = DoHTunnelClient(args.domain)
        if args.send:
            resp = clt.send(args.send)
            print(f"پاسخ (DoH): {resp}")
        else:
            print("DoH client — هر پیام را از طریق HTTPS DNS می‌فرستد")
            while True:
                try:
                    msg  = input("> ").strip()
                    if msg.lower() in ("exit", "quit"):
                        break
                    resp = clt.send(msg)
                    print(f"< {resp}")
                except KeyboardInterrupt:
                    break
        return 0

    p.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
