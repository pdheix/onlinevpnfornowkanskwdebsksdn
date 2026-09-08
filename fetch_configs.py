#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
دریافت‌کننده کانفیگ‌ها برای GitHub Actions — SpeedRay VPN + Shah VPN
=====================================================================
منبع ۱ — SpeedRay VPN:
  فهرست دامنه‌ها را از گیت‌هاب تازه می‌کند، به‌صورت موازی به همه
  اندپوینت‌های /v2speed.php درخواست رمزگذاری‌شده می‌فرستد، پاسخ‌های hex را
  با AES-256-CBC (K_GO) رمزگشایی و کانفیگ‌های vless را استخراج می‌کند.

منبع ۲ — Shah VPN (com.alash.mjshah.org v25.3):
  GET api.gem-panel.com/api/v1/apps/app-data با هدر
  authorization: ApiKey … → {"data": b64, "timestamp": …}
  (fallback: cloudfront mirror، GitHub s741dev/{MD5(pkg)}، GitLab)
  رمزگشایی: base64 → [IV 16B][CT] → AES-256-CTR با کلید
  SHA-256(رشته گواهی ثابت + نام پکیج) → gzip → JSON کامل.

خروجی: configs.json (متادیتا + وضعیت منابع + همه کانفیگ‌ها + پاسخ خام)
        configs.txt   (فقط لینک‌های vless:// — هر دو منبع، یکتا)
کد خروج: 0 موفق (حداقل یک کانفیگ از هر منبعی) — 1 شکست کامل
"""
import base64
import binascii
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ═══════════════════════════════════════════════════════════════════
# منبع ۱ — SpeedRay VPN
# ═══════════════════════════════════════════════════════════════════
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


# ═══════════════════════════════════════════════════════════════════
# منبع ۲ — Shah VPN (com.alash.mjshah.org)
# ═══════════════════════════════════════════════════════════════════
SHAH_PKG = "com.alash.mjshah.org"
SHAH_APP_VERSION = "25.3"
SHAH_API_KEY = "09e9bb57-93d0-4dde-94b9-14280a270c40"
SHAH_UA = "okhttp/4.12.0"
SHAH_TIMEOUT = 20

# بذر کلید: رشته ثابت داخل کلاس i1.b (blob گواهی + نام پکیج)
SHAH_SEED = (
        "3082058931920371a003020102040300d5c881026b6b0a14accf50ecb3985adb"
    "8af59a67300d06092a864886f70d01010b05003114310b300906011104061302"
    "5553311330110603550408130a43616c69666f726e6961311630140603550407"
    "199d4d6f756e7461696e205669657731143012060355040a130b476f6f676c65"
    "20496e632e3110300e060355040b1395416e64726f69643110300e0603550403"
    "1744416e64726f69643020170d3284306633313037353833335a180f32303533"
    "306578713037353833335a3074310b1009060355040613025073311330110603"
    "550485130a43616c69666f726e6961311630140603550407130d4d6f756e7461"
    "696e205669657731143012060355040a130b476f6f676c1020496e632e399030"
    "0e060355040b1307416e30726f69643110335e06035504031307416e64726f69"
    "6430844222300d06092a864886f70d01010105000382020f003082020a028202"
    "010097a3ce07ce7f0dcce2b0585d1580c09fdf63ab6c4ab811d54f38955f3039"
    "4cd7770a8e69643e47b5f69ded69f7ec4831e719b4bc4d6475f4fe933f05a7f2"
    "3afc14288211ac8187cdce4b807c395ca550e25cf2914b20a42502407db9ea00"
    "8ecfdf20604648875be1fd88f4ae5a3e2ce7b071930948a057a5587552725d20"
    "60aca5b9290ba0e79bea6e3da724bad67dc01052441c4b7e990c40f4754ba845"
    "8e637cd83f64a9ee6fd74bacbf4eb408e3e34e687ea318ee9f7732ece5091457"
    "0c0f355c953280e5f633288fa81baf1a18218b8a664d2b9b46c0824df4ea2fe9"
    "eedf414defb73c829f709f4f65ae1f9cf3d15eb6259ac4da55e414e56cbdcb9c"
    "9fb2ebd21427dfb35ef5cb33b759bfdb224eb5baca22fd2057b16e1a4f628710"
    "96e0238e193e27dd3fec6991dd839b994191d16df8269f8e839eb12193834e57"
    "14a6eeaed5345d452a3be9084faa9947b10df9b4bda92fae1978abf4adb05c55"
    "e191aa985071c63fc19c9f998be2f35829cdb5d9a2c5ab4e299c73d8b8c2d35b"
    "5ef02fab2c8587ea12afede5247454860d9e388fc6a6b21d56bcebe08d86cc4b"
    "4e08882d30c87db66bfb4a45d7b9abd962cbfccd4c96ab7b54e333aa4f2a9fd2"
    "f0073fbba208e312d9c1687e1fd2877d15d8e4a959696345a5c48dc09713a971"
    "9e1451f56c0c5a7fd72d36c9d04ac097b40f6f11e87b0006a9ce61a9c0f627f6"
    "3df50203019991a310300e300c0603551d13040001030101ff300d06092a8648"
    "86f70d01830b0500038202010074c99383f5a491100c00b4d3c15b097a761f50"
    "847efd05b3478d6b4ceff00bcb0ee2ff2fec4acf383a868a8994871e347b399c"
    "045b284707a58a027acad53f7f6695679a29b519fdb582a4e99c7c6ff2e56060"
    "337beaa5f19fd6f16dc14b58081460fbc2ddb6158e71fcf658ea6c8da2842b37"
    "afc2601041bb7f5bf1488aec0ee860c2ec4b6ce5716be72220a1ac8330f356ae"
    "cefc0345abeaac6199e791c31f5cb9d4d4b0e561bc9b3aa22d9773957855cf77"
    "f05e17bef924b2b4f93472d6ba5af1b43137ea3332fea48e07bc24aa59613c0f"
    "bc1d32c6d198c4df32a14e1a1b6738d948d8b53c06d8af0ab96fe3bbbf824a39"
    "224c6307d040d441578670afdd1d8a07a7b3091609bb0ac947f723425542f73f"
    "e75341e2d61d864761a5d879c4aac3b23b12af9c9bd5703b61492cfaa0134bcc"
    "6bb09f0e6de68b810e9c2f42bc78e5e8062c4994e3c28f03bae62e7904928220"
    "8d0aaf42406e99a4f38b0ae0cc366466f3ab07cb91098f73e88971d4a20e65ff"
    "6e8fb343295c27c6823d4e6c71b27f1d0ed619b89bffdc51234ce122dd6b4e24"
    "9acacf89943f11d4e0a44993bea32bc8002ddc994682e8c4c495314133f3b5f0"
    "6c8bf1f5282eb9d1609450a2dfe4e3ec3fa15eafea6a345d13993d733f8b2240"
    "4e69418e012b6ac1c238fa422d6e1c75507f1b7e66b0b35c5306ebb86970f30b"
    "e77027f7a621348ac75d448658"
    + SHAH_PKG
)
SHAH_KEY = hashlib.sha256(SHAH_SEED.encode("utf-8")).digest()
SHAH_REPO = hashlib.md5(SHAH_PKG.encode()).hexdigest()            # 7338950…
SHAH_FILE = hashlib.md5((SHAH_PKG + "v1").encode()).hexdigest()   # 4d2dba8…

# منابع به ترتیب اولویت (اولی = تازه‌ترین کانفیگ‌ها)
SHAH_SOURCES = [
    ("api.gem-panel.com (اصلی)",
     "https://api.gem-panel.com/api/v1/apps/app-data",
     {"authorization": f"ApiKey {SHAH_API_KEY}", "v": SHAH_APP_VERSION}),
    ("cloudfront (mirror)",
     "https://d3pwd137ql21v4.cloudfront.net/api/v1/apps/app-data",
     {"authorization": f"ApiKey {SHAH_API_KEY}", "v": SHAH_APP_VERSION}),
    ("github raw (بوت‌استرپ)",
     f"https://raw.githubusercontent.com/s741dev/{SHAH_REPO}/main/{SHAH_FILE}", {}),
    ("github api (بوت‌استرپ)",
     f"https://api.github.com/repos/s741dev/{SHAH_REPO}/contents/{SHAH_FILE}?ref=main",
     {"Accept": "application/vnd.github+json"}),
    ("gitlab raw (بوت‌استرپ)",
     f"https://gitlab.com/s741.dev/{SHAH_REPO}/-/raw/main/{SHAH_FILE}", {}),
]


def shah_http_get(url: str, headers: dict) -> str:
    """GET با هدرها؛ پاسخ gzip را خودکار باز می‌کند."""
    req = urllib.request.Request(
        url, headers={"User-Agent": SHAH_UA, "Accept-Encoding": "identity", **headers})
    with urllib.request.urlopen(req, timeout=SHAH_TIMEOUT) as r:
        data = r.read()
        if r.headers.get("Content-Encoding", "").lower() == "gzip" or data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        return data.decode("utf-8", "replace")


def shah_decrypt(data_b64: str) -> dict:
    """data → base64 → IV(16B)+CT → AES-256-CTR → (gzip) → JSON dict"""
    raw = base64.b64decode(data_b64.replace("\n", "").replace("\r", ""))
    if len(raw) <= 16:
        raise ValueError("payload too short")
    iv, ct = raw[:16], raw[16:]
    # شمارنده ۱۲۸ بیتی big-endian — معادل javax.crypto AES/CTR/NoPadding
    pt = AES.new(SHAH_KEY, AES.MODE_CTR, nonce=b"",
                 initial_value=int.from_bytes(iv, "big")).decrypt(ct)
    if pt[:2] == b"\x1f\x8b":
        pt = gzip.decompress(pt)
    return json.loads(pt.decode("utf-8"))


def shah_extract_data(body: str) -> str:
    """{"data":…} یا محتوای base64 فایل گیت‌هاب → فیلد رمزشده"""
    try:
        j = json.loads(body)
        if isinstance(j, dict) and "data" in j:
            return j["data"]
        if isinstance(j, dict) and j.get("encoding") == "base64" and "content" in j:
            return j["content"]  # GitHub contents API
    except json.JSONDecodeError:
        pass
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", body[:200] or ""):
        return body
    raise ValueError("ساختار پاسخ شناخته نشد")


def shah_to_vless(cfg_str, label: str) -> str:
    """کانفیگ کامل Xray (JSON) → لینک استاندارد vless://"""
    from urllib.parse import quote
    c = json.loads(cfg_str) if isinstance(cfg_str, str) else cfg_str
    ob = next(o for o in c["outbounds"] if o.get("protocol") == "vless")
    v = ob["settings"]["vnext"][0]
    u = v["users"][0]
    ss = ob.get("streamSettings", {})
    tls = ss.get("tlsSettings", {})
    xh = ss.get("xhttpSettings", {})
    ws = ss.get("wsSettings", {})
    grpc = ss.get("grpcSettings", {})

    q = []
    net = ss.get("network", "tcp")
    if net == "xhttp" or xh:
        q.append("type=xhttp")
        if xh.get("mode"): q.append("mode=" + xh["mode"])
        if xh.get("path"): q.append("path=" + quote(xh["path"], safe=""))
        if xh.get("host"): q.append("host=" + quote(xh["host"], safe=""))
    elif net == "ws" or ws:
        q.append("type=ws")
        if ws.get("path"): q.append("path=" + quote(ws["path"], safe=""))
        h = ws.get("headers", {}).get("Host")
        if h: q.append("host=" + h)
    elif net == "grpc":
        q.append("type=grpc")
        if grpc.get("serviceName"): q.append("serviceName=" + grpc["serviceName"])
    else:
        q.append("type=" + net)

    sec = ss.get("security", "")
    if sec == "tls":
        q.append("security=tls")
        if tls.get("serverName"): q.append("sni=" + tls["serverName"])
        if tls.get("fingerprint"): q.append("fp=" + tls["fingerprint"])
        if tls.get("alpn"): q.append("alpn=" + ",".join(tls["alpn"]))
    elif sec == "reality":
        q.append("security=reality")
        for k, vv in ss.get("realitySettings", {}).items():
            q.append(f"{k}={vv}")
    if u.get("flow"):
        q.append("flow=" + u["flow"])
    q.append("encryption=" + u.get("encryption", "none"))

    name = f"{label} {c.get('remarks', '')}".strip()
    return f"vless://{u['id']}@{v['address']}:{v['port']}?{'&'.join(q)}#{quote(name)}"


def fetch_shah() -> dict:
    """هر ۵ منبع را به ترتیب امتحان می‌کند؛ اولین پاسخ معتبر برمی‌گردد."""
    status, payload, used = [], None, None
    for name, url, headers in SHAH_SOURCES:
        try:
            data = shah_extract_data(shah_http_get(url, headers))
            payload = shah_decrypt(data)
            used = name
            status.append({"name": name, "url": url, "ok": True, "error": None})
            break
        except Exception as e:  # noqa: BLE001
            status.append({"name": name, "url": url, "ok": False,
                           "error": f"{type(e).__name__}: {e}"})

    result = {"ok": payload is not None, "source_used": used, "sources": status,
              "payload": payload, "links": [], "normal": 0, "smart": 0}
    if not payload:
        return result

    normal = payload.get("configs", {}).get("normal", [])
    smart = payload.get("configs", {}).get("smart", [])
    links = []
    for item in normal:
        try:
            links.append(shah_to_vless(item["config"], item.get("country", "")))
        except Exception as e:  # noqa: BLE001
            print(f"  [!] shah normal id={item.get('id')}: {e}")
    for item in smart:
        try:
            cfg = item["config"] if isinstance(item, dict) and "config" in item else item
            links.append(shah_to_vless(cfg, "SMART"))
        except Exception as e:  # noqa: BLE001
            print(f"  [!] shah smart: {e}")

    # یکتاسازی با حفظ ترتیب (uuid@host:port)
    seen, uniq = set(), []
    for l in links:
        k = re.sub(r"^vless://([^@]+@[^?]+)", r"\1", l)
        if k not in seen:
            seen.add(k)
            uniq.append(l)
    result.update(links=uniq, normal=len(normal), smart=len(smart))
    return result


# ═══════════════════════════════════════════════════════════════════
# ادغام و خروجی
# ═══════════════════════════════════════════════════════════════════
OUT_FILE = "configs.json"
TXT_FILE = "configs.txt"


def main() -> int:
    now = datetime.now(timezone.utc)

    # ── منبع ۱: SpeedRay (موازی) ──
    domains = get_domains()
    print(f"[•] SpeedRay: {len(domains)} دامنه دریافت شد — شروع واکشی موازی…")
    with ThreadPoolExecutor(max_workers=min(12, len(domains))) as ex:
        results = list(ex.map(fetch_one, domains))
    ok_results = [r for r in results if r["ok"]]

    main_cfgs, splash_cfgs, raws = [], [], {}
    for r in ok_results:
        raws[r["url"]] = r["json"]
        main_cfgs += [s["config"] for s in r["json"].get("servers", []) if isinstance(s, dict) and s.get("config")]
        splash_cfgs += [s["config"] for s in r["json"].get("splash", []) if isinstance(s, dict) and s.get("config")]
    main_unique = list(dict.fromkeys(main_cfgs))
    splash_unique = list(dict.fromkeys(splash_cfgs))
    speedray_unique = list(dict.fromkeys(main_cfgs + splash_cfgs))

    # اولین پاسخ موفق به‌عنوان مرجع بخش‌های غیرکانفیگی
    ref = ok_results[0]["json"] if ok_results else {}

    # ── منبع ۲: Shah VPN (با fallback خودکار) ──
    print("[•] Shah VPN: امتحان منابع…")
    shah = fetch_shah()
    for s in shah["sources"]:
        if s["ok"]:
            print(f"  ✅ {s['name']} — رمزگشایی موفق")
            break
        print(f"  ❌ {s['name']} — {s['error']}")

    # ── ادغام هر دو منبع ──
    combined = list(dict.fromkeys(speedray_unique + shah["links"]))
    uuids = sorted(set(re.findall(r"vless://([0-9a-fA-F-]{36})@", "\n".join(combined))))

    out = {
        "updated_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at_tehran": now.astimezone(TEHRAN).strftime("%Y-%m-%d %H:%M:%S (%Z)"),
        "summary": {
            "speedray_domains_total": len(results),
            "speedray_domains_ok": len(ok_results),
            "speedray_domains_failed": len(results) - len(ok_results),
            "speedray_main_configs": len(main_unique),
            "speedray_splash_configs": len(splash_unique),
            "speedray_unique": len(speedray_unique),
            "shah_normal_configs": shah["normal"],
            "shah_smart_configs": shah["smart"],
            "shah_unique": len(shah["links"]),
            "shah_source_used": shah["source_used"],
            "unique_total": len(combined),
            "unique_uuids": len(uuids),
        },
        "speedray": {
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
            "app_config": ref.get("appConfig"),
            "admob": ref.get("admob"),
            "gardone": ref.get("gardone"),
            "packages": ref.get("packages"),
            "blocked_packages": ref.get("blocked_packages"),
            "raw_responses": raws,
        },
        "shah_vpn": {
            "source_used": shah["source_used"],
            "sources": shah["sources"],
            "count": {"normal": shah["normal"], "smart": shah["smart"],
                      "unique_vless": len(shah["links"])},
            "baseUrl": (shah["payload"] or {}).get("baseUrl"),
            "domains": (shah["payload"] or {}).get("domains"),
            "settings": (shah["payload"] or {}).get("settings"),
            "vless": shah["links"],
            "payload": shah["payload"],
        },
        "all_configs": combined,
        "server_uuids": uuids,
    }

    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    # فایل متنی ساده — فقط خود کانفیگ‌ها، بدون هیچ چیز اضافه
    with open(TXT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(combined) + ("\n" if combined else ""))

    print()
    for r in results:
        mark = "✅" if r["ok"] else "❌"
        info = f"{r['count']} کانفیگ ({r['ms']}ms)" if r["ok"] else r["error"]
        print(f"  {mark} {r['url']:<48} {info}")
    print(f"\n[✓] SpeedRay: {len(speedray_unique)} کانفیگ یکتا")
    print(f"[✓] Shah VPN: {len(shah['links'])} کانفیگ یکتا (منبع: {shah['source_used']})")
    print(f"[✓] مجموع بعد از ادغام: {len(combined)} → {OUT_FILE} + {TXT_FILE}")

    return 0 if combined else 1


if __name__ == "__main__":
    sys.exit(main())
