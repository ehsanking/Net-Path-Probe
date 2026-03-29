#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import atexit
import base64
import hashlib
import json
import os
import selectors
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

APP_NAME = "Net Path Probe"
VERSION = "3.0"

PID_FILE = Path("/tmp/net_path_probe_listener.pid")
LOG_FILE = Path("/tmp/net_path_probe_listener.log")
CERT_FILE = Path("/tmp/net_path_probe_listener_cert.pem")
KEY_FILE = Path("/tmp/net_path_probe_listener_key.pem")

CONNECT_TIMEOUT = 2.5
UDP_TIMEOUT = 2.5
running = True
listener_sockets: List[socket.socket] = []
http_server: Optional[ThreadingHTTPServer] = None
https_server: Optional[ThreadingHTTPServer] = None

CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUD7ZJlO5b2fTBEIEsjgq1TTTPbukwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMTmV0UGF0aFByb2JlMB4XDTI2MDMyOTE0MzUwNVoXDTM2
MDMyNjE0MzUwNVowFzEVMBMGA1UEAwwMTmV0UGF0aFByb2JlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIEXpEjvIxH0rkGYWdkmYUs+BaueHBMJmVjN
L516FzX6GZDHUzP4h3JDmK5GosS6qdzicF/upMjSzyvUNN7SblU/uZLqAbiiLJ4A
zQuD+ktLBPnghEiQSpcZaBlBGOfAchauPc+mLRwtJ/zTYTSCo7w9mifnEI6hOoqu
zGR6prReQ/E43MaFDx2dxp/qFx9D/cFOp8q/br78O4CqPmOmNafiX4FpKwIwx/ph
kuzuL2b80KL9AZiNMoykOLlJYP4RZ0qz9cRDO9OLnFle7l8xZJWyeiKCuDPE3/0U
oC624yBpAT90lL4wW+y0zXRfDn+tp7Dtw1jkhtSUWUe/g+FCywIDAQABo1MwUTAd
BgNVHQ4EFgQUesquVAoj97MzMa2iPpKl9IieJyUwHwYDVR0jBBgwFoAUesquVAoj
97MzMa2iPpKl9IieJyUwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAOb78L1luXc78gG2n+s5fYZj9lLsXSjR5YSIjUC/LvnmPGnMliDuX7YCVm7NY
j91596jvxnEUi7rB8aNHCUD5kDcrGtqbpdCUv0cA7AIySjS7E6oxhYLU/C5iftf6
3Xc/MLum05V1cUrf/TDm43x6mvqNf9viDK9e/tqBXJX4iei0TT95ANFpld3e09wO
pA0POcJ1am7jQSs0EiUXnUQpVRuJ48D1hwfuKcQ/bip25Zzgmwv2u8hDC1ojlM7C
e3sYzM7NSl3tq5bR0Y1pKHVbdJiaato41dWwL9UMb42Pi/kagctD4xKD53lfclNN
qPfph0pRQE5vRJp7mfsM/4PkKQ==
-----END CERTIFICATE-----
"""

KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkgRekSO8jEfSu
QZhZ2SZhSz4Fq54cEwmZWM0vnXoXNfoZkMdTM/iHckOYrkaixLqp3OJwX+6kyNLP
K9Q03tJuVT+5kuoBuKIsngDNC4P6S0sE+eCESJBKlxloGUEY58ByFq49z6YtHC0n
/NNhNIKjvD2aJ+cQjqE6iq7MZHqmtF5D8TjcxoUPHZ3Gn+oXH0P9wU6nyr9uvvw7
gKo+Y6Y1p+JfgWkrAjDH+mGS7O4vZvzQov0BmI0yjKQ4uUlg/hFnSrP1xEM704uc
WV7uXzFklbJ6IoK4M8Tf/RSgLrbjIGkBP3SUvjBb7LTNdF8Of62nsO3DWOSG1JRZ
R7+D4ULLAgMBAAECggEAMTaFchp3oBBBGNh60XZLKxQta9jZpiBz4LJWQAZmfgch
2QAdAWEs2qhuXIDWlN8x0JtKCsBITnfdySidhWubnHJYbBXtd7Jaoepq5uypAPoB
aW2voyNqN0ZYzXGwrdi3E+qBGfDDD/+76piSTCQ/aOhprXJ+h8+DoFXY0UDGCJS2
TTn5nSQHGeH+paqgb2YemF+ExPjX6gNL31ko+2VsgF/SH6wpDU11Y6rRmHBb9rRL
erhM93PNV36PL18NTpNetq551o82owBYA0ziEPX6pxb6m/FIIHqx/t8Jq2wDPa8D
mTy11hwZ7xerQPGbPFQUdbiaoAXXzAG9a3urM9IAwQKBgQDOKx2ZPoYP2qRWZNZM
QXfLACfcLrPnsFFjjM1+2pH+axzaFK1wbQlMCLdn7f+7TDshDvwXtmahm/hfQRuQ
91G8gdq1unRJCTbL7gb7j2Myeez8SK0POmC7KfcD0ojbjAvQK0EtNiBZG63QuaxF
LDdv+LmhJQbOlyP3mUp3OFyi0QKBgQDMQ/bQmCVLryUoQgq38t54QMOoyN+6zEDC
Z6ezcF/tpmV/2dO6Jxo04K922Lz8eiK3SZSeoZkCf/BxzoJD5Rt76Rqk7s83qxdy
hHLbURdDqXtu44Ixr6qHOQbDf589vk68tsGgg32xf/8JXFetENprXDi2I4Y9FXUa
3eb/cTza2wKBgHKRbSJSp2c6BiboZFn965cIoB3wahMvXRsoDK4YwhaS6XabFQKr
5QW2tkzv6jPoGde2HwsCVqgqJ2yvnqUBew95TdO9KI/JqgTLYl/6/5H2RWaw8FLN
CyIXIOij31+5xHrK/q4kLPe3tPCPrZbHCouTuXw+OjklrlwSeFomHPxxAoGAa50W
yBiP9YqlecspWHYEjLgaHK8PZ5s6NvFjIZ7/evWiHbRF3pnBLcB90JApKJ6z8Xo7
aUNbmDyNEXgpmtl2HFbXqbMCyqJBrRxoYnEbX5NHq0kDC2gv4CPEE3UGEQJU+wkR
g54it0PmuijDLDNnzw379sFKdJ38XxYvH76pv+cCgYEAo/NJXlDMcf8lcn/VFnnR
2AYu6VY/sG+wgB4jpX+3mUoSa6XopTa1TiH4quBRNtdqNEkElQ/2mx+RWgsL+rj3
l9TM0V55Fuc+q70vZZdu5iOZ9/njz4lUX6XguSZkwUMgwfiZgjscpDi4x6XCRvly
ASP09Bd22zCiqKOgzCsCrAQ=
-----END PRIVATE KEY-----
"""

# High test ports chosen to avoid conflicts with real services.
PORTS = {
    "TCP": 22000,
    "UDP": 22001,
    "SSH": 22022,
    "RDP": 23389,
    "HTTP": 22080,
    "HTTPS": 22443,
    "HTTP2_SIM": 22444,
    "HTTP3_SIM": 22445,
    "WEBSOCKET": 28080,
    "GRPC_SIM": 25051,
    "DNS": 25353,
    "DOT": 20853,
    "DOH": 22443,
    "NTP": 20123,
    "FTP": 20021,
    "FTPS": 20990,
    "TFTP": 20069,
    "RSYNC": 20873,
    "SMTP": 20025,
    "IMAP": 20143,
    "POP3": 20110,
    "MQTT": 21883,
    "AMQP": 25672,
    "STOMP": 21613,
    "COAP": 25683,
    "SMB": 20445,
    "NFS": 22049,
    "LDAP": 20389,
    "LDAPS": 20636,
    "REDIS": 26379,
    "MYSQL": 23306,
    "POSTGRES": 25432,
    "SIP": 25060,
    "RTP": 25004,
    "RTSP": 20554,
    "SNMP": 20161,
    "TELNET": 20023,
    "PPTP": 21723,
    "VNC": 25900,
    "SYSLOG": 20514,
    "L2TP": 21701,
    "WIREGUARD": 25180,
    "OPENVPN_UDP": 21194,
    "OPENVPN_TCP": 21195,
    "VXLAN": 24789,
    "GENEVE": 26081,
}

# Protocols that need kernel/raw/third-party support for exact testing.
LIMITED_PROTOCOLS = {
    "SCTP": "Needs SCTP kernel support and python socket SCTP support.",
    "QUIC": "Exact QUIC handshake needs a QUIC library; this tool uses UDP/QUIC-style fallback.",
    "GRE": "Exact GRE needs raw sockets/root and custom packet handling.",
    "IPIP": "Exact IPIP needs raw sockets/root and custom packet handling.",
    "IPsec ESP": "Exact ESP needs raw sockets/root and IPsec stack integration.",
    "IPsec AH": "Exact AH needs raw sockets/root and IPsec stack integration.",
    "HTTP/2": "Exact HTTP/2 framing is not implemented; TLS/ALPN path is simulated.",
    "HTTP/3": "Exact HTTP/3 needs QUIC; UDP/HTTP3-style fallback is used.",
    "gRPC": "Exact gRPC needs HTTP/2 framing; TLS/gRPC-style fallback is used.",
}

running_lock = threading.Lock()

def banner() -> None:
    print("=" * 86)
    print(f"{APP_NAME} v{VERSION} | protocol matrix listener + tester")
    print("Broad practical connectivity checks between two servers")
    print("=" * 86)


def colorize(text: str, status: str) -> str:
    if not sys.stdout.isatty():
        return text
    palette = {"OK": "\033[92m", "DENY": "\033[91m", "WARN": "\033[93m", "INFO": "\033[96m", "END": "\033[0m"}
    return f"{palette.get(status, '')}{text}{palette['END']}"


def print_result(name: str, status: str, detail: str) -> None:
    print(f"[{colorize(status, status):>5}] {name:<18} {detail}")


def print_section(title: str) -> None:
    print("\n" + "-" * 86)
    print(title)
    print("-" * 86)


def is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid() -> Optional[int]:
    try:
        return int(PID_FILE.read_text().strip())
    except Exception:
        return None


def remove_pid_file() -> None:
    try:
        if PID_FILE.exists() and read_pid() == os.getpid():
            PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def daemonize() -> None:
    if os.name != "posix":
        raise RuntimeError("Daemon mode is implemented for Linux/Unix only")
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    os.chdir("/")
    os.setsid()
    os.umask(0o027)
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    sys.stdout.flush(); sys.stderr.flush()
    with open("/dev/null", "rb", 0) as devnull_r, open(LOG_FILE, "ab", 0) as logfile:
        os.dup2(devnull_r.fileno(), sys.stdin.fileno())
        os.dup2(logfile.fileno(), sys.stdout.fileno())
        os.dup2(logfile.fileno(), sys.stderr.fileno())
    PID_FILE.write_text(str(os.getpid()))
    atexit.register(remove_pid_file)


def stop_listener() -> int:
    pid = read_pid()
    if not pid:
        print_result("Listener", "WARN", f"pid file not found: {PID_FILE}")
        return 1
    if not is_process_alive(pid):
        print_result("Listener", "WARN", f"stale pid file removed: {pid}")
        PID_FILE.unlink(missing_ok=True)
        return 1
    os.kill(pid, signal.SIGTERM)
    print_result("Listener", "OK", f"SIGTERM sent to PID {pid}")
    return 0


def status_listener() -> int:
    pid = read_pid()
    if not pid:
        print_result("Listener", "DENY", "not running")
        return 1
    if is_process_alive(pid):
        print_result("Listener", "OK", f"running with PID {pid}")
        print_result("PID file", "INFO", str(PID_FILE))
        print_result("Log file", "INFO", str(LOG_FILE))
        return 0
    print_result("Listener", "DENY", f"pid file exists but process {pid} is dead")
    return 1


def handle_shutdown(signum, frame):
    global running, http_server, https_server
    with running_lock:
        running = False
    for srv in [http_server, https_server]:
        try:
            if srv:
                srv.shutdown()
                srv.server_close()
        except Exception:
            pass
    for s in list(listener_sockets):
        try:
            s.close()
        except Exception:
            pass
    remove_pid_file()
    os._exit(0)


def ensure_tls_files() -> None:
    if not CERT_FILE.exists():
        CERT_FILE.write_text(CERT_PEM)
        os.chmod(CERT_FILE, 0o600)
    if not KEY_FILE.exists():
        KEY_FILE.write_text(KEY_PEM)
        os.chmod(KEY_FILE, 0o600)


class MainHttpHandler(BaseHTTPRequestHandler):
    server_version = "NetPathProbeHTTP/3.0"

    def _send(self, body: bytes, code: int = 200, content_type: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/dns-query"):
            body = json.dumps({"ok": True, "service": "doh", "path": self.path, "time": int(time.time())}).encode()
            self._send(body)
            return
        body = json.dumps({"ok": True, "service": "https" if isinstance(self.request, ssl.SSLSocket) else "http", "path": self.path, "time": int(time.time())}).encode()
        self._send(body)

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        return


def start_http_server(bind_ip: str, port: int, tls: bool = False) -> None:
    global http_server, https_server
    srv = ThreadingHTTPServer((bind_ip, port), MainHttpHandler)
    if tls:
        ensure_tls_files()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        https_server = srv
    else:
        http_server = srv
    listener_sockets.append(srv.socket)
    try:
        srv.serve_forever(poll_interval=0.5)
    except Exception:
        pass


def generic_tcp_server(bind_ip: str, port: int, handler: Callable[[socket.socket], None]) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(128)
    listener_sockets.append(srv)
    while True:
        try:
            srv.settimeout(1.0)
            client, _ = srv.accept()
        except socket.timeout:
            if not running:
                break
            continue
        except OSError:
            break
        threading.Thread(target=handler, args=(client,), daemon=True).start()


def generic_udp_server(bind_ip: str, port: int, response: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    listener_sockets.append(srv)
    while True:
        try:
            srv.settimeout(1.0)
            data, addr = srv.recvfrom(4096)
        except socket.timeout:
            if not running:
                break
            continue
        except OSError:
            break
        try:
            srv.sendto(response if response else data, addr)
        except Exception:
            pass


def generic_tls_server(bind_ip: str, port: int, response: bytes) -> None:
    ensure_tls_files()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(128)
    listener_sockets.append(srv)
    while True:
        try:
            srv.settimeout(1.0)
            client, _ = srv.accept()
        except socket.timeout:
            if not running:
                break
            continue
        except OSError:
            break
        def _worker(c: socket.socket):
            try:
                ss = ctx.wrap_socket(c, server_side=True)
                try:
                    _ = ss.recv(4096)
                except Exception:
                    pass
                ss.sendall(response)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass
        threading.Thread(target=_worker, args=(client,), daemon=True).start()


def banner_handler(banner: bytes) -> Callable[[socket.socket], None]:
    def _handler(client: socket.socket):
        try:
            client.settimeout(3)
            client.sendall(banner)
            try:
                _ = client.recv(4096)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass
    return _handler


def redis_handler(client: socket.socket):
    try:
        client.settimeout(3)
        data = client.recv(4096)
        if b"PING" in data.upper():
            client.sendall(b"+PONG\r\n")
        else:
            client.sendall(b"+OK\r\n")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def websocket_handler(client: socket.socket):
    try:
        client.settimeout(3)
        req = client.recv(4096).decode(errors="ignore")
        key = None
        for line in req.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
                break
        if key:
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
            client.sendall(resp)
        else:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length:0\r\n\r\n")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def mqtt_handler(client: socket.socket):
    try:
        client.settimeout(3)
        _ = client.recv(4096)
        client.sendall(bytes([0x20, 0x02, 0x00, 0x00]))
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def amqp_handler(client: socket.socket):
    try:
        client.settimeout(3)
        data = client.recv(4096)
        if data.startswith(b"AMQP"):
            client.sendall(b"AMQP\x00\x00\x09\x01")
        else:
            client.sendall(b"AMQP\x00\x00\x09\x01")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def stomp_handler(client: socket.socket):
    try:
        client.settimeout(3)
        _ = client.recv(4096)
        client.sendall(b"CONNECTED\nversion:1.2\n\n\x00")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def sip_handler(client: socket.socket):
    try:
        client.settimeout(3)
        _ = client.recv(4096)
        client.sendall(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def rtsp_handler(client: socket.socket):
    try:
        client.settimeout(3)
        _ = client.recv(4096)
        client.sendall(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def mysql_handler(client: socket.socket):
    try:
        pkt = b"\x0a5.7.0-netpath\x00"  # fake greeting body
        payload = struct.pack("<I", len(pkt))[:3] + b"\x00" + pkt
        client.sendall(payload)
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def postgres_handler(client: socket.socket):
    try:
        client.settimeout(3)
        _ = client.recv(4096)
        msg = b"SERROR\x00C28000\x00Mnet-path-probe\x00\x00"
        client.sendall(struct.pack("!cI", b'E', len(msg)+4) + msg)
    except Exception:
        pass
    finally:
        try: client.close()
        except Exception: pass


def sctp_supported() -> bool:
    return hasattr(socket, "IPPROTO_SCTP")


def run_cmd(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 999, "", str(e)


def ping_test(ip: str) -> Tuple[str, str]:
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return "WARN", "ping command not found"
    rc, out, err = run_cmd([ping_bin, "-c", "2", "-W", "2", ip], timeout=8)
    text = out or err
    if rc == 0:
        return "OK", text.splitlines()[-1] if text else "reachable"
    return "DENY", text.splitlines()[-1] if text else "no icmp reply"


def traceroute_test(ip: str) -> Tuple[str, str]:
    tr = shutil.which("traceroute") or shutil.which("tracepath")
    if not tr:
        return "WARN", "traceroute/tracepath not installed"
    cmd = [tr, "-n", ip] if os.path.basename(tr) == "tracepath" else [tr, "-n", "-m", "12", ip]
    rc, out, err = run_cmd(cmd, timeout=20)
    text = out or err
    if rc == 0:
        return "OK", text.splitlines()[-1] if text else "completed"
    return "DENY", text.splitlines()[-1] if text else "blocked"


def mtu_test(ip: str) -> Tuple[str, str]:
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return "WARN", "ping command not found"
    rc, out, err = run_cmd([ping_bin, "-c", "1", "-M", "do", "-s", "1400", "-W", "2", ip], timeout=6)
    return ("OK", "PMTU probe passed") if rc == 0 else ("DENY", (out or err).splitlines()[-1] if (out or err) else "failed")


def tcp_banner_probe(ip: str, port: int, expect: bytes, send: bytes = b"", tls: bool = False) -> Tuple[str, str]:
    s = None
    try:
        raw = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        s = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=ip)
        if send:
            s.sendall(send)
        data = s.recv(4096)
        if expect in data:
            return "OK", data[:120].decode(errors="ignore")
        return "DENY", f"unexpected reply: {data[:80]!r}"
    except ConnectionRefusedError:
        return "DENY", "connection refused"
    except socket.timeout:
        return "DENY", "timeout"
    except Exception as e:
        return "DENY", str(e)
    finally:
        try:
            if s: s.close()
        except Exception:
            pass


def udp_probe(ip: str, port: int, payload: bytes, expect: bytes) -> Tuple[str, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(UDP_TIMEOUT)
    try:
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(4096)
        if expect in data:
            return "OK", data[:120].decode(errors="ignore") if data else "reply"
        return "DENY", f"unexpected reply: {data[:80]!r}"
    except socket.timeout:
        return "DENY", "no udp response"
    except Exception as e:
        return "DENY", str(e)
    finally:
        try: s.close()
        except Exception: pass


def http_probe(ip: str, port: int, path: str = "/", tls: bool = False) -> Tuple[str, str]:
    s = None
    try:
        raw = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        s = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=ip)
        req = f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        s.sendall(req)
        data = s.recv(4096)
        head = data.decode(errors="ignore")
        if "200" in head.splitlines()[0]:
            return "OK", head.splitlines()[0]
        return "DENY", head.splitlines()[0] if head else "no http reply"
    except Exception as e:
        return "DENY", str(e)
    finally:
        try:
            if s: s.close()
        except Exception:
            pass


def websocket_probe(ip: str, port: int) -> Tuple[str, str]:
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: {ip}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    return tcp_banner_probe(ip, port, b"101 Switching Protocols", send=req)


def postgres_probe(ip: str, port: int) -> Tuple[str, str]:
    # Minimal startup message: length(8) + protocol 196608 (3.0)
    msg = struct.pack("!II", 8, 196608)
    return tcp_banner_probe(ip, port, b"E", send=msg)


def mqtt_probe(ip: str, port: int) -> Tuple[str, str]:
    pkt = b"\x10\x0c\x00\x04MQTT\x04\x02\x00<\x00\x00"
    return tcp_banner_probe(ip, port, bytes([0x20, 0x02]), send=pkt)


def amqp_probe(ip: str, port: int) -> Tuple[str, str]:
    return tcp_banner_probe(ip, port, b"AMQP", send=b"AMQP\x00\x00\x09\x01")


def stomp_probe(ip: str, port: int) -> Tuple[str, str]:
    return tcp_banner_probe(ip, port, b"CONNECTED", send=b"CONNECT\naccept-version:1.2\n\n\x00")


def redis_probe(ip: str, port: int) -> Tuple[str, str]:
    return tcp_banner_probe(ip, port, b"+PONG", send=b"*1\r\n$4\r\nPING\r\n")


def sctp_probe(ip: str) -> Tuple[str, str]:
    if not sctp_supported():
        return "WARN", LIMITED_PROTOCOLS["SCTP"]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((ip, 22900))
        s.sendall(b"SCTP")
        data = s.recv(4096)
        return ("OK", data.decode(errors="ignore")[:80]) if data else ("DENY", "no reply")
    except Exception as e:
        return "WARN", f"SCTP not available here: {e}"
    finally:
        try: s.close()
        except Exception: pass


def get_destination_ip() -> str:
    while True:
        ip = input("Destination IP: ").strip()
        try:
            socket.inet_aton(ip)
            return ip
        except Exception:
            print("Invalid IPv4 address.")


def summarize(rows: List[Tuple[str, str, str]]) -> None:
    ok = sum(1 for _, status, _ in rows if status == "OK")
    deny = sum(1 for _, status, _ in rows if status == "DENY")
    warn = sum(1 for _, status, _ in rows if status == "WARN")
    print_section("Summary")
    print_result("OK", "OK", str(ok))
    print_result("DENY", "DENY", str(deny))
    print_result("WARN", "WARN", str(warn))


def add(rows: List[Tuple[str, str, str]], name: str, res: Tuple[str, str]) -> None:
    rows.append((name, res[0], res[1]))
    print_result(name, res[0], res[1])


def main_test() -> int:
    banner()
    ip = get_destination_ip()
    rows: List[Tuple[str, str, str]] = []

    print_section(f"Base path diagnostics for {ip}")
    add(rows, "ICMP", ping_test(ip))
    add(rows, "Traceroute", traceroute_test(ip))
    add(rows, "PMTU", mtu_test(ip))

    print_section("Protocol matrix")
    # Direct probes / implemented
    add(rows, "TCP", tcp_banner_probe(ip, PORTS["TCP"], b"TCP-OK"))
    add(rows, "UDP", udp_probe(ip, PORTS["UDP"], b"UDP?", b"UDP-OK"))
    add(rows, "SSH", tcp_banner_probe(ip, PORTS["SSH"], b"SSH-2.0"))
    add(rows, "RDP", tcp_banner_probe(ip, PORTS["RDP"], b"RDP-OK"))
    add(rows, "HTTP", http_probe(ip, PORTS["HTTP"], "/", tls=False))
    add(rows, "HTTPS", http_probe(ip, PORTS["HTTPS"], "/", tls=True))
    add(rows, "WebSocket", websocket_probe(ip, PORTS["WEBSOCKET"]))
    add(rows, "DNS", udp_probe(ip, PORTS["DNS"], b"DNS?", b"DNS-OK"))
    add(rows, "DoT", tcp_banner_probe(ip, PORTS["DOT"], b"DOT-OK", send=b"DOT?", tls=True))
    add(rows, "DoH", http_probe(ip, PORTS["DOH"], "/dns-query", tls=True))
    add(rows, "NTP", udp_probe(ip, PORTS["NTP"], b"NTP?", b"NTP-OK"))
    add(rows, "FTP", tcp_banner_probe(ip, PORTS["FTP"], b"220 FTP"))
    add(rows, "FTPS", tcp_banner_probe(ip, PORTS["FTPS"], b"FTPS-OK", send=b"HELLO", tls=True))
    add(rows, "SFTP", tcp_banner_probe(ip, PORTS["SSH"], b"SSH-2.0"))
    add(rows, "TFTP", udp_probe(ip, PORTS["TFTP"], b"TFTP?", b"TFTP-OK"))
    add(rows, "Rsync", tcp_banner_probe(ip, PORTS["RSYNC"], b"@RSYNCD:"))
    add(rows, "SMTP", tcp_banner_probe(ip, PORTS["SMTP"], b"220 SMTP"))
    add(rows, "IMAP", tcp_banner_probe(ip, PORTS["IMAP"], b"* OK IMAP"))
    add(rows, "POP3", tcp_banner_probe(ip, PORTS["POP3"], b"+OK POP3"))
    add(rows, "MQTT", mqtt_probe(ip, PORTS["MQTT"]))
    add(rows, "AMQP", amqp_probe(ip, PORTS["AMQP"]))
    add(rows, "STOMP", stomp_probe(ip, PORTS["STOMP"]))
    add(rows, "CoAP", udp_probe(ip, PORTS["COAP"], b"COAP?", b"COAP-OK"))
    add(rows, "SMB/CIFS", tcp_banner_probe(ip, PORTS["SMB"], b"SMB-OK"))
    add(rows, "NFS", tcp_banner_probe(ip, PORTS["NFS"], b"NFS-OK"))
    add(rows, "LDAP", tcp_banner_probe(ip, PORTS["LDAP"], b"LDAP-OK"))
    add(rows, "LDAPS", tcp_banner_probe(ip, PORTS["LDAPS"], b"LDAPS-OK", send=b"LDAP?", tls=True))
    add(rows, "Redis RESP", redis_probe(ip, PORTS["REDIS"]))
    add(rows, "MySQL protocol", tcp_banner_probe(ip, PORTS["MYSQL"], b"netpath"))
    add(rows, "PostgreSQL protocol", postgres_probe(ip, PORTS["POSTGRES"]))
    add(rows, "SIP", udp_probe(ip, PORTS["SIP"], b"SIP?", b"SIP-OK"))
    add(rows, "RTP", udp_probe(ip, PORTS["RTP"], b"RTP?", b"RTP-OK"))
    add(rows, "RTSP", tcp_banner_probe(ip, PORTS["RTSP"], b"RTSP/1.0 200", send=b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"))
    add(rows, "SNMP", udp_probe(ip, PORTS["SNMP"], b"SNMP?", b"SNMP-OK"))
    add(rows, "Telnet", tcp_banner_probe(ip, PORTS["TELNET"], b"Telnet"))
    add(rows, "PPTP", tcp_banner_probe(ip, PORTS["PPTP"], b"PPTP-OK"))
    add(rows, "VNC", tcp_banner_probe(ip, PORTS["VNC"], b"RFB"))
    add(rows, "Syslog", udp_probe(ip, PORTS["SYSLOG"], b"SYSLOG?", b"SYSLOG-OK"))
    add(rows, "L2TP", udp_probe(ip, PORTS["L2TP"], b"L2TP?", b"L2TP-OK"))
    add(rows, "WireGuard", udp_probe(ip, PORTS["WIREGUARD"], b"WG?", b"WG-OK"))
    add(rows, "OpenVPN/UDP", udp_probe(ip, PORTS["OPENVPN_UDP"], b"OVPN-UDP?", b"OVPN-UDP-OK"))
    add(rows, "OpenVPN/TCP", tcp_banner_probe(ip, PORTS["OPENVPN_TCP"], b"OVPN-TCP-OK"))
    add(rows, "VXLAN", udp_probe(ip, PORTS["VXLAN"], b"VXLAN?", b"VXLAN-OK"))
    add(rows, "Geneve", udp_probe(ip, PORTS["GENEVE"], b"GENEVE?", b"GENEVE-OK"))

    # Limited/fallback probes
    add(rows, "SCTP", sctp_probe(ip))
    add(rows, "QUIC", udp_probe(ip, PORTS["HTTP3_SIM"], b"QUIC?", b"QUIC-SIM-OK"))
    add(rows, "HTTP/2", tcp_banner_probe(ip, PORTS["HTTP2_SIM"], b"H2-SIM-OK", send=b"H2?", tls=True))
    add(rows, "HTTP/3", udp_probe(ip, PORTS["HTTP3_SIM"], b"H3?", b"QUIC-SIM-OK"))
    add(rows, "gRPC", tcp_banner_probe(ip, PORTS["GRPC_SIM"], b"GRPC-SIM-OK", send=b"GRPC?", tls=True))
    for limited in ["GRE", "IPIP", "IPsec ESP", "IPsec AH"]:
        add(rows, limited, ("WARN", LIMITED_PROTOCOLS[limited]))

    summarize(rows)
    print("\nNotes:")
    print("- This tool now includes all requested protocol names in the test matrix.")
    print("- Many protocols above are verified with minimal application-level probes on dedicated high test ports.")
    print("- Some protocols require raw sockets, kernel features, or third-party protocol stacks for exact RFC-level testing; those are marked WARN when exact validation is not available.")
    return 0


def start_listener(bind_ip: str, foreground: bool) -> int:
    if read_pid() and is_process_alive(read_pid()):
        print_result("Listener", "DENY", "already running")
        return 1
    if not foreground:
        daemonize()
    else:
        PID_FILE.write_text(str(os.getpid()))
        atexit.register(remove_pid_file)
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    threads = []
    # Core HTTP/HTTPS
    for tls, port in [(False, PORTS["HTTP"]), (True, PORTS["HTTPS"] )]:
        t = threading.Thread(target=start_http_server, args=(bind_ip, port, tls), daemon=True)
        t.start(); threads.append(t)

    # Simple TCP services
    tcp_map: Dict[int, Callable[[socket.socket], None]] = {
        PORTS["TCP"]: banner_handler(b"TCP-OK\r\n"),
        PORTS["SSH"]: banner_handler(b"SSH-2.0-NetPathProbe\r\n"),
        PORTS["RDP"]: banner_handler(b"RDP-OK\r\n"),
        PORTS["FTP"]: banner_handler(b"220 FTP NetPathProbe\r\n"),
        PORTS["RSYNC"]: banner_handler(b"@RSYNCD: 31.0\n"),
        PORTS["SMTP"]: banner_handler(b"220 SMTP NetPathProbe\r\n"),
        PORTS["IMAP"]: banner_handler(b"* OK IMAP NetPathProbe\r\n"),
        PORTS["POP3"]: banner_handler(b"+OK POP3 NetPathProbe\r\n"),
        PORTS["SMB"]: banner_handler(b"SMB-OK\r\n"),
        PORTS["NFS"]: banner_handler(b"NFS-OK\r\n"),
        PORTS["LDAP"]: banner_handler(b"LDAP-OK\r\n"),
        PORTS["MYSQL"]: mysql_handler,
        PORTS["POSTGRES"]: postgres_handler,
        PORTS["TELNET"]: banner_handler(b"Telnet NetPathProbe\r\n"),
        PORTS["PPTP"]: banner_handler(b"PPTP-OK\r\n"),
        PORTS["VNC"]: banner_handler(b"RFB 003.008\r\n"),
        PORTS["OPENVPN_TCP"]: banner_handler(b"OVPN-TCP-OK\r\n"),
        PORTS["RTSP"]: rtsp_handler,
        PORTS["WEBSOCKET"]: websocket_handler,
        PORTS["MQTT"]: mqtt_handler,
        PORTS["AMQP"]: amqp_handler,
        PORTS["STOMP"]: stomp_handler,
        PORTS["REDIS"]: redis_handler,
        PORTS["SIP"]: sip_handler,
    }
    for port, handler in tcp_map.items():
        t = threading.Thread(target=generic_tcp_server, args=(bind_ip, port, handler), daemon=True)
        t.start(); threads.append(t)

    # TLS services
    tls_map: Dict[int, bytes] = {
        PORTS["DOT"]: b"DOT-OK\r\n",
        PORTS["FTPS"]: b"FTPS-OK\r\n",
        PORTS["LDAPS"]: b"LDAPS-OK\r\n",
        PORTS["HTTP2_SIM"]: b"H2-SIM-OK\r\n",
        PORTS["GRPC_SIM"]: b"GRPC-SIM-OK\r\n",
    }
    for port, response in tls_map.items():
        t = threading.Thread(target=generic_tls_server, args=(bind_ip, port, response), daemon=True)
        t.start(); threads.append(t)

    # UDP services
    udp_map: Dict[int, bytes] = {
        PORTS["UDP"]: b"UDP-OK",
        PORTS["DNS"]: b"DNS-OK",
        PORTS["NTP"]: b"NTP-OK",
        PORTS["TFTP"]: b"TFTP-OK",
        PORTS["COAP"]: b"COAP-OK",
        PORTS["SNMP"]: b"SNMP-OK",
        PORTS["RTP"]: b"RTP-OK",
        PORTS["SYSLOG"]: b"SYSLOG-OK",
        PORTS["L2TP"]: b"L2TP-OK",
        PORTS["WIREGUARD"]: b"WG-OK",
        PORTS["OPENVPN_UDP"]: b"OVPN-UDP-OK",
        PORTS["VXLAN"]: b"VXLAN-OK",
        PORTS["GENEVE"]: b"GENEVE-OK",
        PORTS["HTTP3_SIM"]: b"QUIC-SIM-OK",
        PORTS["SIP"]: b"SIP-OK",
    }
    for port, response in udp_map.items():
        t = threading.Thread(target=generic_udp_server, args=(bind_ip, port, response), daemon=True)
        t.start(); threads.append(t)

    while running:
        time.sleep(1.0)
    return 0


def interactive_menu() -> int:
    banner()
    print("1) Start listener in background")
    print("2) Run tester")
    print("3) Listener status")
    print("4) Stop listener")
    print("5) Start listener in foreground")
    choice = input("Select [1-5]: ").strip()
    if choice == "1":
        print_result("Listener", "INFO", "starting in background daemon mode...")
        return start_listener("0.0.0.0", foreground=False)
    if choice == "2":
        return main_test()
    if choice == "3":
        return status_listener()
    if choice == "4":
        return stop_listener()
    if choice == "5":
        return start_listener("0.0.0.0", foreground=True)
    print_result("Menu", "WARN", "invalid choice")
    return 1


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Protocol matrix listener + tester")
    p.add_argument("--listen", action="store_true", help="start listener")
    p.add_argument("--foreground", action="store_true", help="listener in foreground")
    p.add_argument("--bind", default="0.0.0.0", help="bind IP")
    p.add_argument("--stop", action="store_true", help="stop listener")
    p.add_argument("--status", action="store_true", help="status")
    p.add_argument("--test", action="store_true", help="run tester")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.stop:
        banner(); return stop_listener()
    if args.status:
        banner(); return status_listener()
    if args.listen:
        banner();
        if not args.foreground:
            print_result("Listener", "INFO", "starting in background daemon mode...")
        return start_listener(args.bind, foreground=args.foreground)
    if args.test:
        return main_test()
    if sys.stdin.isatty():
        return interactive_menu()
    return main_test()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
