#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cdn_path_finder.py  —  لایه ۲: یافتن IP های باز CDN برای عبور از فیلتر

این ماژول IP های CDN هایی را که دولت‌ها باز نگه می‌دارند
اسکن می‌کند تا مسیری برای relay کردن ترافیک پیدا کند.

استفاده:
    python3 cdn_path_finder.py --scan-cloudflare --target your-server.com
    python3 cdn_path_finder.py --scan-all       --target your-server.com
"""

import ipaddress
import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

CONNECT_TIMEOUT = 3.0
HTTP_TIMEOUT    = 5.0
MAX_WORKERS     = 64
RESULTS_FILE    = "cdn_open_ips.json"

# ─────────────────────────────────────────────────────────────
# رنج‌های IP عمومی CDN های اصلی
# منبع: https://www.cloudflare.com/ips/
#        https://api.fastly.com/public-ip-list
#        https://github.com/nicholasMeadows/AkamaiIPRanges
# ─────────────────────────────────────────────────────────────
CDN_RANGES: Dict[str, List[str]] = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13",   "104.24.0.0/14",   "108.162.192.0/18",
        "131.0.72.0/22",   "141.101.64.0/18",  "162.158.0.0/15",
        "172.64.0.0/13",   "173.245.48.0/20",  "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ],
    "fastly": [
        "23.235.32.0/20",  "43.249.72.0/22",  "103.244.50.0/24",
        "103.245.222.0/23","103.245.224.0/24","104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17","146.75.0.0/17",
        "151.101.0.0/16",  "157.52.192.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22",  "199.27.72.0/21",
        "199.232.0.0/16",
    ],
    "akamai": [
        "2.16.0.0/13",     "23.0.0.0/12",     "23.192.0.0/11",
        "69.192.0.0/16",   "72.246.0.0/15",   "88.221.0.0/16",
        "92.122.0.0/15",   "96.6.0.0/15",     "184.24.0.0/13",
        "184.50.0.0/15",   "184.84.0.0/14",
    ],
    "bunny": [
        "185.181.48.0/22", "192.189.0.0/16",
    ],
}

# ─────────────────────────────────────────────────────────────
# رنگ‌بندی ترمینال
# ─────────────────────────────────────────────────────────────
def _c(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

ok   = lambda t: _c(t, "92")
deny = lambda t: _c(t, "91")
warn = lambda t: _c(t, "93")
info = lambda t: _c(t, "96")


# ─────────────────────────────────────────────────────────────
# یافتن IP های باز
# ─────────────────────────────────────────────────────────────
def tcp_open(ip: str, port: int = 443) -> bool:
    """بررسی اینکه پورت TCP روی این IP باز است."""
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
            return True
    except Exception:
        return False


def https_reachable(ip: str, host_header: str = "", path: str = "/") -> Tuple[bool, int, float]:
    """
    یک درخواست HTTPS به IP می‌فرستد و کد پاسخ + تأخیر را برمی‌گرداند.
    host_header می‌تواند برای domain fronting استفاده شود.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    t0 = time.monotonic()
    try:
        conn = socket.create_connection((ip, 443), timeout=HTTP_TIMEOUT)
        tls  = ctx.wrap_socket(conn, server_hostname=host_header or ip)
        header = host_header or ip
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {header}\r\n"
            "User-Agent: curl/7.88.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        tls.sendall(req)
        resp = tls.recv(4096).decode(errors="ignore")
        tls.close()
        latency = (time.monotonic() - t0) * 1000
        code = 0
        first = resp.split("\r\n", 1)[0]
        if "HTTP/" in first:
            try:
                code = int(first.split()[1])
            except Exception:
                pass
        return True, code, latency
    except Exception:
        return False, 0, (time.monotonic() - t0) * 1000


def expand_range(cidr: str, max_ips: int = 256) -> List[str]:
    """یک رنج CIDR را به لیست IP تبدیل می‌کند (با shuffle برای تنوع)."""
    net  = ipaddress.ip_network(cidr, strict=False)
    ips  = [str(h) for h in net.hosts()]
    if len(ips) > max_ips:
        random.shuffle(ips)
        ips = ips[:max_ips]
    return ips


def scan_cdn(
    cdn_name: str,
    ranges: List[str],
    port: int = 443,
    host_header: str = "",
    max_ips: int = 50,
    workers: int = MAX_WORKERS,
) -> List[Dict]:
    """
    IP های یک CDN را اسکن می‌کند و نتایج را بر اساس تأخیر مرتب می‌کند.
    """
    all_ips: List[str] = []
    for cidr in ranges:
        all_ips.extend(expand_range(cidr, max_ips // len(ranges) + 1))
    random.shuffle(all_ips)
    all_ips = all_ips[:max_ips]

    results = []
    lock    = threading.Lock()

    def probe(ip: str):
        reachable, code, latency = https_reachable(ip, host_header, "/")
        if reachable:
            entry = {"ip": ip, "cdn": cdn_name, "code": code, "latency_ms": round(latency, 1)}
            with lock:
                results.append(entry)
                print(f"  {ok('✓')} {ip:>16}  HTTP {code}  {latency:6.0f} ms")

    print(info(f"\n[{cdn_name}] اسکن {len(all_ips)} IP روی پورت {port} ..."))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, ip): ip for ip in all_ips}
        for f in as_completed(futures):
            _ = f  # خطاها داخل probe مدیریت می‌شوند

    results.sort(key=lambda r: r["latency_ms"])
    return results


# ─────────────────────────────────────────────────────────────
# Domain Fronting — پوشش ترافیک با یک دامنه مجاز
# ─────────────────────────────────────────────────────────────
def domain_front_test(
    cdn_ip: str,
    front_domain: str,
    real_host: str,
    path: str = "/",
) -> Tuple[bool, int, str]:
    """
    Domain Fronting:
    - SNI و Host را front_domain می‌گذارد (دامنه‌ای که فیلتر نیست)
    - اما درخواست به real_host هدایت می‌شود (اگر هر دو روی یک CDN باشند)
    
    این تکنیک روی CDN هایی که allow می‌کنند کار می‌کند.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        conn = socket.create_connection((cdn_ip, 443), timeout=HTTP_TIMEOUT)
        # SNI = front_domain (دامنه غیر فیلتر)
        tls  = ctx.wrap_socket(conn, server_hostname=front_domain)
        # Host header = real_host (سرور واقعی شما)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {real_host}\r\n"
            "User-Agent: curl/7.88.1\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        tls.sendall(req)
        resp  = tls.recv(4096).decode(errors="ignore")
        tls.close()
        code  = 0
        first = resp.split("\r\n", 1)[0]
        if "HTTP/" in first:
            try:
                code = int(first.split()[1])
            except Exception:
                pass
        success = code in (200, 301, 302, 204)
        return success, code, resp.split("\r\n")[0]
    except Exception as e:
        return False, 0, str(e)


# ─────────────────────────────────────────────────────────────
# Cloudflare Worker به عنوان relay پروکسی
# ─────────────────────────────────────────────────────────────
WORKER_SCRIPT_TEMPLATE = """\
// Cloudflare Worker — relay proxy
// در داشبورد Cloudflare Workers ایجاد کنید
// این worker درخواست را به سرور شما forward می‌کند

const TARGET = "https://{target_host}";

export default {{
  async fetch(request, env) {{
    const url = new URL(request.url);
    const targetUrl = TARGET + url.pathname + url.search;
    
    const newRequest = new Request(targetUrl, {{
      method:  request.method,
      headers: request.headers,
      body:    request.body,
    }});
    
    return fetch(newRequest);
  }},
}};
"""

def generate_worker_script(target_host: str) -> str:
    return WORKER_SCRIPT_TEMPLATE.format(target_host=target_host)


# ─────────────────────────────────────────────────────────────
# ذخیره و بارگذاری نتایج
# ─────────────────────────────────────────────────────────────
def save_results(results: List[Dict], path: str = RESULTS_FILE) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(info(f"\n[ذخیره] {len(results)} IP در {path}"))


def load_results(path: str = RESULTS_FILE) -> List[Dict]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def best_ips(results: List[Dict], top_n: int = 5) -> List[Dict]:
    """سریع‌ترین IP های پیدا شده را برمی‌گرداند."""
    return sorted(results, key=lambda r: r["latency_ms"])[:top_n]


# ─────────────────────────────────────────────────────────────
# رابط خط فرمان
# ─────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="یافتن IP های باز CDN برای عبور از فیلتر")
    p.add_argument("--scan-cloudflare", action="store_true", help="اسکن IP های Cloudflare")
    p.add_argument("--scan-fastly",     action="store_true", help="اسکن IP های Fastly")
    p.add_argument("--scan-akamai",     action="store_true", help="اسکن IP های Akamai")
    p.add_argument("--scan-all",        action="store_true", help="اسکن همه CDN ها")
    p.add_argument("--target",          default="",          help="دامنه سرور شما")
    p.add_argument("--front",           default="",          help="دامنه front برای domain fronting")
    p.add_argument("--max-ips",         type=int, default=60,help="حداکثر IP برای اسکن هر CDN")
    p.add_argument("--show-best",       action="store_true", help="نمایش بهترین IP های ذخیره‌شده")
    p.add_argument("--gen-worker",      action="store_true", help="تولید اسکریپت Cloudflare Worker")
    args = p.parse_args()

    if args.show_best:
        results = load_results()
        top = best_ips(results, 10)
        print(info(f"\n{'IP':>18}  {'CDN':<12}  {'Code':>5}  {'Latency':>10}"))
        print("-" * 56)
        for r in top:
            print(f"  {r['ip']:>16}  {r['cdn']:<12}  {r['code']:>5}  {r['latency_ms']:>8.0f} ms")
        return 0

    if args.gen_worker:
        if not args.target:
            print(deny("[خطا] --target لازم است"))
            return 1
        script = generate_worker_script(args.target)
        fname  = "worker_relay.js"
        with open(fname, "w") as f:
            f.write(script)
        print(ok(f"[Worker] اسکریپت در {fname} ذخیره شد"))
        print(info("در داشبورد Cloudflare Workers → Create Worker بارگذاری کنید"))
        return 0

    to_scan = []
    if args.scan_all or args.scan_cloudflare:
        to_scan.append(("cloudflare", CDN_RANGES["cloudflare"]))
    if args.scan_all or args.scan_fastly:
        to_scan.append(("fastly",     CDN_RANGES["fastly"]))
    if args.scan_all or args.scan_akamai:
        to_scan.append(("akamai",     CDN_RANGES["akamai"]))

    if not to_scan:
        p.print_help()
        return 1

    all_results = []
    for cdn_name, ranges in to_scan:
        found = scan_cdn(
            cdn_name, ranges,
            host_header=args.front or args.target,
            max_ips=args.max_ips,
        )
        all_results.extend(found)
        print(info(f"[{cdn_name}] {len(found)} IP باز پیدا شد"))

    if all_results:
        save_results(all_results)
        print(info("\nبهترین IP ها:"))
        for r in best_ips(all_results, 5):
            print(f"  {ok('✓')} {r['ip']:>16}  {r['cdn']:<12}  {r['latency_ms']:.0f} ms")

        # تست domain fronting اگر target و front داده شده
        if args.target and args.front and all_results:
            best = all_results[0]["ip"]
            print(info(f"\n[Domain Fronting] تست با {best} ..."))
            success, code, first_line = domain_front_test(
                best, args.front, args.target
            )
            if success:
                print(ok(f"  ✓ Domain fronting کار کرد! HTTP {code}"))
            else:
                print(warn(f"  ⚠ Domain fronting کار نکرد: {first_line}"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
