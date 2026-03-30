#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smart_relay.py  —  موتور هوشمند انتخاب مسیر

اتوماتیک تمام لایه‌ها را امتحان می‌کند:
  لایه ۱ → مستقیم
  لایه ۲ → CDN (از فایل cdn_open_ips.json)
  لایه ۳ → DNS تانل / DoH

خروجی: بهترین مسیر موجود

استفاده:
    python3 smart_relay.py --target your-server.com --port 443
"""

import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ایمپورت ماژول‌های محلی
try:
    from cdn_path_finder import https_reachable, load_results, best_ips, CDN_RANGES, scan_cdn
    from dns_tunnel       import DnsTunnelClient, DoHTunnelClient, DOMAIN
except ImportError:
    print("فایل‌های cdn_path_finder.py و dns_tunnel.py باید در همین پوشه باشند")
    raise

CONNECT_TIMEOUT = 3.0

def _c(t, code):
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t

ok_   = lambda t: _c(t, "92")
deny_ = lambda t: _c(t, "91")
warn_ = lambda t: _c(t, "93")
info_ = lambda t: _c(t, "96")


# ─────────────────────────────────────────────────────────────
class PathResult:
    def __init__(self, method: str, ok: bool, latency_ms: float, detail: str):
        self.method     = method
        self.ok         = ok
        self.latency_ms = latency_ms
        self.detail     = detail

    def __repr__(self):
        status = ok_("OK") if self.ok else deny_("FAIL")
        return f"[{status}] {self.method:<22} {self.latency_ms:6.0f} ms  {self.detail}"


# ─────────────────────────────────────────────────────────────
# لایه ۱: اتصال مستقیم
# ─────────────────────────────────────────────────────────────
def try_direct(host: str, port: int = 443) -> PathResult:
    t0 = time.monotonic()
    try:
        conn = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        conn.close()
        ms = (time.monotonic() - t0) * 1000
        return PathResult("direct-tcp", True, ms, f"{host}:{port}")
    except Exception as e:
        ms = (time.monotonic() - t0) * 1000
        return PathResult("direct-tcp", False, ms, str(e))


def try_direct_https(host: str) -> PathResult:
    t0 = time.monotonic()
    reachable, code, ms = https_reachable(host, host, "/")
    return PathResult("direct-https", reachable, ms, f"HTTP {code}")


# ─────────────────────────────────────────────────────────────
# لایه ۲: CDN relay
# ─────────────────────────────────────────────────────────────
def try_cdn_relay(host: str, cdn_results_file: str = "cdn_open_ips.json") -> List[PathResult]:
    results_data = load_results(cdn_results_file)
    if not results_data:
        return [PathResult("cdn-relay", False, 9999, "cdn_open_ips.json پیدا نشد — اول اسکن کنید")]
    top = best_ips(results_data, 5)
    path_results = []
    for entry in top:
        ip     = entry["ip"]
        cdn    = entry["cdn"]
        t0     = time.monotonic()
        ok_r, code, ms = https_reachable(ip, host, "/")
        path_results.append(PathResult(
            f"cdn-{cdn}", ok_r, ms,
            f"via {ip}  HTTP {code}"
        ))
    return path_results


def try_cdn_quick_scan(host: str) -> Optional[PathResult]:
    """اگر نتایج CDN موجود نبود، یک اسکن سریع Cloudflare انجام می‌دهد."""
    print(warn_("  [CDN] نتایج قدیمی یافت نشد — اسکن سریع Cloudflare ..."))
    found = scan_cdn("cloudflare", CDN_RANGES["cloudflare"], host_header=host, max_ips=20, workers=30)
    if found:
        best  = found[0]
        ok_r, code, ms = https_reachable(best["ip"], host, "/")
        return PathResult("cdn-cloudflare", ok_r, ms, f"via {best['ip']}  HTTP {code}")
    return None


# ─────────────────────────────────────────────────────────────
# لایه ۳: DNS تانل
# ─────────────────────────────────────────────────────────────
def try_dns_tunnel(dns_server: str, domain: str = DOMAIN) -> PathResult:
    t0  = time.monotonic()
    clt = DnsTunnelClient(dns_server, port=5353, domain=domain)
    try:
        resp = clt.send('{"msg":"ping","ts":' + str(int(time.time())) + '}')
        ms   = (time.monotonic() - t0) * 1000
        if resp:
            return PathResult("dns-tunnel-udp", True, ms, f"پاسخ: {resp[:60]}")
        return PathResult("dns-tunnel-udp", False, ms, "بدون پاسخ")
    except Exception as e:
        ms = (time.monotonic() - t0) * 1000
        return PathResult("dns-tunnel-udp", False, ms, str(e))


def try_doh_tunnel(domain: str = DOMAIN) -> PathResult:
    t0  = time.monotonic()
    clt = DoHTunnelClient(domain)
    try:
        resp = clt.send('{"msg":"ping"}')
        ms   = (time.monotonic() - t0) * 1000
        if resp:
            return PathResult("dns-tunnel-doh", True, ms, f"پاسخ: {resp[:60]}")
        return PathResult("dns-tunnel-doh", False, ms, "بدون پاسخ")
    except Exception as e:
        ms = (time.monotonic() - t0) * 1000
        return PathResult("dns-tunnel-doh", False, ms, str(e))


# ─────────────────────────────────────────────────────────────
# موتور اصلی
# ─────────────────────────────────────────────────────────────
def discover_best_path(
    target_host: str,
    target_port: int = 443,
    dns_server:  str = "",
    domain:      str = DOMAIN,
) -> Optional[PathResult]:
    """
    تمام مسیرها را امتحان می‌کند و بهترین را برمی‌گرداند.
    """
    all_results: List[PathResult] = []
    banner = "=" * 60
    print(f"\n{banner}")
    print(f"  کشف مسیر به {target_host}:{target_port}")
    print(f"{banner}")

    # لایه ۱
    print(info_("\n[لایه ۱] اتصال مستقیم"))
    r = try_direct(target_host, target_port)
    print(f"  {r}")
    all_results.append(r)
    if r.ok and r.latency_ms < 500:
        print(ok_("\n✓ اتصال مستقیم کار می‌کند!"))
        return r

    r2 = try_direct_https(target_host)
    print(f"  {r2}")
    all_results.append(r2)
    if r2.ok:
        print(ok_("\n✓ HTTPS مستقیم کار می‌کند!"))
        return r2

    # لایه ۲
    print(info_("\n[لایه ۲] مسیریابی CDN"))
    cdn_path = None
    if Path("cdn_open_ips.json").exists():
        cdn_results = try_cdn_relay(target_host)
        for cr in cdn_results:
            print(f"  {cr}")
            all_results.append(cr)
            if cr.ok and not cdn_path:
                cdn_path = cr
    else:
        cdn_path = try_cdn_quick_scan(target_host)
        if cdn_path:
            print(f"  {cdn_path}")
            all_results.append(cdn_path)

    if cdn_path and cdn_path.ok:
        print(ok_(f"\n✓ مسیر CDN پیدا شد: {cdn_path.detail}"))
        return cdn_path

    # لایه ۳
    print(info_("\n[لایه ۳] تانل DNS"))
    if dns_server:
        r3 = try_dns_tunnel(dns_server, domain)
        print(f"  {r3}")
        all_results.append(r3)
        if r3.ok:
            print(ok_("\n✓ تانل DNS کار می‌کند!"))
            return r3

    r4 = try_doh_tunnel(domain)
    print(f"  {r4}")
    all_results.append(r4)
    if r4.ok:
        print(ok_("\n✓ تانل DoH (DNS over HTTPS) کار می‌کند!"))
        return r4

    # خلاصه
    print(f"\n{banner}")
    working = [r for r in all_results if r.ok]
    if working:
        best = min(working, key=lambda r: r.latency_ms)
        print(ok_(f"بهترین مسیر: {best}"))
        return best
    print(deny_("هیچ مسیری پیدا نشد."))
    print(warn_("پیشنهاد: --dns-server را با IP سرور مقصد تنظیم کنید"))
    return None


# ─────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="موتور هوشمند کشف مسیر اتصال")
    p.add_argument("--target",     required=True,       help="هاست یا IP مقصد")
    p.add_argument("--port",       type=int, default=443, help="پورت (پیش‌فرض: 443)")
    p.add_argument("--dns-server", default="",          help="IP سرور DNS تانل (اختیاری)")
    p.add_argument("--domain",     default=DOMAIN,      help="دامنه DNS تانل")
    args = p.parse_args()

    result = discover_best_path(args.target, args.port, args.dns_server, args.domain)
    return 0 if (result and result.ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
