"""Stage: which discovered hosts actually answer on http/https (same logic as the curl -k -L loop)."""
import re

import requests
import urllib3

from ..findings import make
from ..util import UA, log, pmap

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def probe(host, proto):
    url = f"{proto}://{host}"
    try:
        r = requests.get(url, verify=False, allow_redirects=True, timeout=(5, 10), headers={"User-Agent": UA}, stream=True)
        body = r.raw.read(20000, decode_content=True).decode("utf-8", "ignore")
        m = TITLE_RE.search(body)
        try:
            cookies = r.raw.headers.getlist("Set-Cookie")
        except Exception:
            cookies = []
        # headers of the final response
        return {"host": host, "proto": proto, "url": url, "code": r.status_code, "final_url": r.url,
                "title": (m.group(1).strip()[:120] if m else ""), "server": r.headers.get("Server", ""),
                "headers": {k.lower(): v for k, v in r.headers.items()}, "set_cookie": cookies,
                "redirected_https": r.url.startswith("https://")}
    except Exception as e:
        return {"host": host, "proto": proto, "url": url, "code": 0, "error": type(e).__name__}


def run(ctx):
    if ctx.cached("liveness"):
        return
    hosts = [h for h, v in ctx.data["subdomains"]["hosts"].items() if v["resolves"]]
    log(f"Probing {len(hosts)} resolving hosts on https/http")
    jobs = [(h, p) for h in hosts for p in ("https", "http")]
    results = pmap(lambda j: probe(*j), jobs, workers=ctx.workers)
    with open(ctx.raw("Active_Domains.txt"), "w") as f:  # same format as the manual script
        for r in results:
            f.write(f"{r['proto']}://{r['host']} [{r['code']:03d}]\n")
    live = [r for r in results if r["code"]]
    ctx.save("liveness", live)
    log(f"{len({r['host'] for r in live})} live hosts")
    # HTTP served without redirect to HTTPS while HTTPS is also available
    by = {}
    for r in live:
        by.setdefault(r["host"], {})[r["proto"]] = r
    for h, d in by.items():
        if "http" in d and "https" in d and not d["http"]["redirected_https"] and d["http"]["code"] < 400:
            root = ctx.data["subdomains"]["hosts"][h]["root"]
            ctx.add(make(root, h, "Headers", "http_no_redirect", url=d["http"]["url"], evidence=f"http -> {d['http']['final_url']} [{d['http']['code']}]"))
