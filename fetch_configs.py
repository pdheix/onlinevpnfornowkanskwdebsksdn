#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SpeedRay VPN — دریافت‌کننده کانفیگ‌ها برای GitHub Actions
==========================================================
فهرست دامنه‌ها را از گیت‌هاب تازه می‌کند، به‌صورت موازی به همه
اندپوینت‌های /v2speed.php درخواست رمزگذاری‌شده می‌فرستد، پاسخ‌های hex را
با AES-256-CBC رمزگشایی و نتیجه کامل را در configs.json ذخیره می‌کند.

خروجی: configs.json (متادیتا + وضعیت دامنه‌ها + همه کانفیگ‌ها + پاسخ خام)
کد خروج: 0 موفق (حداقل یک کانفیگ) — 1 شکست کامل
"""
import base64
import binascii
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ─────────────── ثابت‌های استخراج‌شده از libgojni.so ───────────────
K_GO = b"GbT]Lpn(b{ot3j#m@1!mrmV7z043q9we"        # کلید AES فرم و پاسخ (تابع r)
K_JAVA = b"d#fggs!12bvnhg23#12fgirt#24*900@"      # کلید سمت جاوا (مرجع)
CERT_MD5 = "1C9CAD11EFF098AB05EC987440DFE3D2"     # MD5 گواهی امضا (بزرگ)
APP_CODE = "50"
UA = "Nexen-HTTP/2.0"
PATH_EP = "/v2speed.php"
DOMAIN_LIST_URL = "https://raw.githubusercontent.com/nonkh/xoxz/main/api-domain2.txt"
FALLBACK_DOMAINS = [
    "https://akhtarbuy.uk", "https://akhtarbuy.com", "https://akhtarbuy.net",
    "https://akhtarbuy.org", "https://akhtarbuy.cc", "https://akhtarbuy.work",
    "https://tmzara.com", "https://sirjanha.com",
    "https://piransharrudaw-events.com", "https://almaktoom.org",
]
TIMEOUT = 25          # ثانیه — برای هر دامنه
OUT_FILE = "configs.json"
TXT_FILE = "configs.txt"
TEHRAN = timezone(timedelta(hours=3), "Iran Standard Time")


def aes_enc(pt: str) -> str:
    """hex(AES-256-CBC(pt, K_GO, IV=K_GO[:16])) با پدینگ PKCS7"""
    c = AES.new(K_GO, AES.MODE_CBC, K_GO[:16])
    return binascii.hexlify(c.encrypt(pad(pt.encode(), 16))).decode()


def aes_dec(hexdata: str) -> str:
    ct = binascii.unhexlify(hexdata.strip())
    pt = AES.new(K_GO, AES.MODE_CBC, K_GO[:16]).decrypt(ct)
    return unpad(pt, 16).decode("utf-8")


def build_body() -> bytes:
    """فرم رمزگذاری‌شده — third باید زمان لحظه درخواست باشد."""
    dev = base64.b64encode("9a7f3c2e5b1d8046|1750000000000".encode()).decode() + "\n"
    form = {
        "app_code":  aes_enc(APP_CODE),
        "app_token": aes_enc("nil"),
        "dev":       aes_enc(dev),
        "fourth":    aes_enc("Asia/Tehran"),
        "s":         aes_enc("nil"),
        "third":     aes_enc(str(int(time.time() * 1000))),
        "twain":     aes_enc(CERT_MD5),
    }
    return urllib.parse.urlencode(form).encode()  # مرتب‌سازی الفبایی مثل Go


def http_post(url: str, body: bytes) -> tuple:
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", UA)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read(), None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def get_domains() -> list:
    try:
        req = urllib.request.Request(DOMAIN_LIST_URL, method="GET")
        req.add_header("User-Agent", UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read())
        urls = [u["url"] for u in j.get("urls", []) if u.get("method") == "POST" and u.get("url")]
        if urls:
            return urls
    except Exception:  # noqa: BLE001
        pass
    return FALLBACK_DOMAINS


def fetch_one(base: str) -> dict:
    """یک دامنه → وضعیت + JSON رمزگشایی‌شده (یا خطا)"""
    url = base.rstrip("/") + PATH_EP
    t0 = time.time()
    data, err = http_post(url, build_body())
    ms = int((time.time() - t0) * 1000)
    if err:
        return {"url": url, "ok": False, "ms": ms, "count": 0, "error": err, "json": None}
    t = data.strip()
    # decoy = HTML
    if not t or t[:1] == b"<" or b"<html" in t[:300].lower() or b"<!doctype" in t[:300].lower():
        return {"url": url, "ok": False, "ms": ms, "count": 0, "error": "decoy/HTML", "json": None}
    try:
        j = json.loads(aes_dec(t.decode("ascii", "strict")))
        n = len(j.get("servers", [])) + len(j.get("splash", []))
        return {"url": url, "ok": True, "ms": ms, "count": n, "error": None, "json": j}
    except Exception as e:  # noqa: BLE001
        return {"url": url, "ok": False, "ms": ms, "count": 0, "error": f"decrypt/parse: {e}", "json": None}


def main() -> int:
    now = datetime.now(timezone.utc)
    domains = get_domains()
    print(f"[•] {len(domains)} دامنه دریافت شد — شروع واکشی موازی…")

    with ThreadPoolExecutor(max_workers=min(12, len(domains))) as ex:
        results = list(ex.map(fetch_one, domains))

    ok_results = [r for r in results if r["ok"]]

    # ادغام و حذف تکراری
    main_cfgs, splash_cfgs, raws = [], [], {}
    for r in ok_results:
        raws[r["url"]] = r["json"]
        main_cfgs += [s["config"] for s in r["json"].get("servers", []) if isinstance(s, dict) and s.get("config")]
        splash_cfgs += [s["config"] for s in r["json"].get("splash", []) if isinstance(s, dict) and s.get("config")]
    main_unique = list(dict.fromkeys(main_cfgs))
    splash_unique = list(dict.fromkeys(splash_cfgs))
    all_unique = list(dict.fromkeys(main_cfgs + splash_cfgs))

    # اولین پاسخ موفق به‌عنوان مرجع بخش‌های غیرکانفیگی
    ref = ok_results[0]["json"] if ok_results else {}

    import re
    uuids = sorted(set(re.findall(r"vless://([0-9a-fA-F-]{36})@", "\n".join(all_unique))))

    out = {
        "updated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at_tehran": now.astimezone(TEHRAN).strftime("%Y-%m-%d %H:%M:%S (%Z)"),
        "summary": {
            "domains_total": len(results),
            "domains_ok": len(ok_results),
            "domains_failed": len(results) - len(ok_results),
            "main_configs": len(main_unique),
            "splash_configs": len(splash_unique),
            "unique_total": len(all_unique),
            "unique_uuids": len(uuids),
        },
        "domains": [
            {
                "url": r["url"],
                "ok": r["ok"],
                "http_ms": r["ms"],
                "config_count": r["count"],
                "error": r["error"],
            }
            for r in results
        ],
        "main_servers": main_unique,
        "splash_servers": splash_unique,
        "all_configs": all_unique,
        "server_uuids": uuids,
        "app_config": ref.get("appConfig"),
        "admob": ref.get("admob"),
        "gardone": ref.get("gardone"),
        "packages": ref.get("packages"),
        "blocked_packages": ref.get("blocked_packages"),
        "raw_responses": raws,
    }

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # فایل متنی ساده — فقط خود کانفیگ‌ها، بدون هیچ چیز اضافه
    with open(TXT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(all_unique) + ("\n" if all_unique else ""))

    for r in results:
        mark = "✅" if r["ok"] else "❌"
        info = f"{r['count']} کانفیگ ({r['ms']}ms)" if r["ok"] else r["error"]
        print(f"  {mark} {r['url']:<48} {info}")
    print(f"\n[✓] {len(all_unique)} کانفیگ یکتا → {OUT_FILE}")

    return 0 if all_unique else 1


if __name__ == "__main__":
    sys.exit(main())
