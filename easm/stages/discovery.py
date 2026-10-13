"""Stage 0: keyword-driven discovery of domains you may own but haven't listed, plus look-alike domains."""
import json
import re

from ..findings import make
from ..resolver import make_resolver, query
from ..util import have, http_get, log, norm_domain, pmap, retry_json, run as run_cmd, valid_domain

TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "net.in", "org.in", "co.za", "com.br", "co.nz", "com.sg", "co.jp", "com.mx", "com.cn", "ae.org"}
TLDS = ["com", "net", "org", "io", "co", "in", "co.in", "ai", "app", "dev", "info", "biz", "us", "uk", "co.uk", "de", "fr", "nl", "ru", "su", "pl", "au", "com.au", "cn", "online", "tech", "cloud", "xyz"]


def registrable(host):
    p = host.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in TWO_LEVEL:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def label_of(d):
    p = d.split(".")
    return p[-3] if len(p) >= 3 and ".".join(p[-2:]) in TWO_LEVEL else p[-2]


def keyword_candidates(ctx):
    found = {}
    for kw in ctx.keywords:
        data = retry_json(f"https://crt.sh/?q=%25{kw}%25&output=json", timeout=90) or []
        for row in data:
            for n in row.get("name_value", "").split("\n"):
                n = norm_domain(n)
                if "*" in n or not valid_domain(n):
                    continue
                reg = registrable(n)
                if kw in label_of(reg):
                    found.setdefault(reg, set()).add(kw)
        log(f"keyword '{kw}': {len(found)} candidate domains so far")
    return {d: sorted(k) for d, k in found.items() if d not in ctx.roots and not ctx.excluded(d)}


def permutations(domain):
    lab, tld = label_of(domain), domain[len(label_of(domain)) + 1:]
    out = set()
    for t in TLDS:
        out.add(f"{lab}.{t}")
    for i in range(len(lab)):
        out.add(f"{lab[:i]}{lab[i+1:]}.{tld}")           # omission
        out.add(f"{lab[:i]}{lab[i]}{lab[i:]}.{tld}")       # repetition
        if 0 < i:
            out.add(f"{lab[:i]}-{lab[i:]}.{tld}")          # hyphenation
    for pre in ("my", "get", "the"):
        out.add(f"{pre}{lab}.{tld}")
    for suf in ("group", "online", "login", "secure", "support"):
        out.add(f"{lab}{suf}.{tld}")
    out = {d for d in out if valid_domain(d) and d != domain}
    return sorted(out)


def rdap(domain):
    d = retry_json(f"https://rdap.org/domain/{domain}", tries=2, timeout=15) or {}
    name = org = ""
    for e in d.get("entities", []):
        if "registrant" in e.get("roles", []):
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn": name = item[3]
                if item[0] == "org": org = item[3] if isinstance(item[3], str) else " ".join(item[3])
    return {"registrant_name": name, "registrant_org": org}


def similar_for(ctx, domain):
    res = make_resolver(ctx.resolvers)
    if have("dnstwist"):
        _, out = run_cmd(["dnstwist", "--registered", "--nameservers", ",".join(ctx.resolvers), "--format", "json", domain], timeout=900)
        try:
            cands = sorted({r["domain"] for r in json.loads(out) if r.get("domain") and r["domain"] != domain})
        except Exception:
            cands = permutations(domain)
    else:
        cands = permutations(domain)
    live = [c for c, ips in zip(cands, pmap(lambda c: (query(res, c, "A") or []) + (query(res, c, "MX") or []) + (query(res, c, "NS") or []), cands, workers=ctx.workers)) if ips]
    # only RDAP the resolving ones, capped
    reg = dict(zip(live[:40], pmap(rdap, live[:40], workers=5)))
    from .webchecks import tls_check
    certs = dict(zip(live[:40], pmap(lambda c: tls_check(c), live[:40], workers=8)))
    rows = []
    for c in live:
        r = reg.get(c, {})
        t = certs.get(c, {})
        rows.append({"domain": domain, "similar": c, "registrant_name": r.get("registrant_name", ""), "registrant_org": r.get("registrant_org", ""),
                     "cert": {k: t.get(k, "") for k in ("issuer", "subject", "not_before", "not_after")} if t.get("not_after") else None})
    return rows


def run(ctx):
    if ctx.cached("discovery"):
        return
    cand = keyword_candidates(ctx) if ctx.keywords else {}
    sim = []
    for rows in pmap(lambda d: similar_for(ctx, d), ctx.roots, workers=2):
        sim.extend(rows)
    for r in sim:
        ctx.add(make(r["domain"], r["similar"], "Similar", "similar_domain", evidence=f"Registrant: {r['registrant_org'] or r['registrant_name'] or 'unknown'}",
                     extra={"id": r["similar"]}))
    ctx.save("discovery", {"candidates": cand, "similar": sim})
    if cand:
        log(f"{len(cand)} keyword-matched domains NOT in scope - review in the report (use --include-discovered to scan them)")
    if ctx.include_discovered:
        ctx.roots = sorted(set(ctx.roots) | set(cand))
