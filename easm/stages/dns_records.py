"""Stage: email/DNS records per root domain (DMARC, SPF, DKIM, MX, NS, CAA, AXFR)."""
import re

import dns.query
import dns.zone

from ..findings import make
from ..resolver import make_resolver, query
from ..util import log, pmap

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "s1", "s2", "dkim", "mandrill", "smtp", "zoho", "mxvault"]


def _tags(rec):
    out = {}
    for part in rec.strip('"').split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def _txt(res, name):
    """TXT strings, or None if the lookup failed."""
    r = query(res, name, "TXT")
    return None if r is None else [t.replace('" "', "").strip('"') for t in r]


def _spf_lookups(res, record, depth=0, seen=None):
    seen = seen or set()
    n = 0
    for tok in record.split():
        t = tok.lower().lstrip("+-~?")
        if t.startswith("include:"):
            target = t.split(":", 1)[1]
            n += 1
            if target not in seen and depth < 5:
                seen.add(target)
                for r in (_txt(res, target) or []):
                    if r.lower().startswith("v=spf1"):
                        n += _spf_lookups(res, r, depth + 1, seen)
        elif t.startswith(("a:", "mx:", "ptr", "exists:", "redirect=")) or t in ("a", "mx"):
            n += 1
    return n


def _axfr(ns_host, domain):
    try:
        ips = query(make_resolver(["8.8.8.8"]), ns_host.rstrip("."), "A") or []
        for ip in ips[:1]:
            z = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=6, lifetime=10))
            return sorted(str(n) for n in z.nodes.keys())
    except Exception:
        pass
    return None


def analyze(ctx, domain):
    res = make_resolver(ctx.resolvers)
    rec = {"domain": domain}
    probes = {t: query(res, domain, t) for t in ("NS", "MX", "A")}
    txt = _txt(res, domain)
    if txt is None and all(v is None for v in probes.values()):
        log(f"{domain}: DNS lookups all failed (resolver unreachable?) - skipping record checks, NOT reporting missing records", "!")
        return {"domain": domain, "error": "dns_lookup_failed"}, []
    rec["ns"] = sorted(probes["NS"] or [])
    rec["mx"] = sorted(probes["MX"] or [])
    rec["a"] = sorted(probes["A"] or [])
    rec["caa"] = query(res, domain, "CAA") or []
    txt_failed = txt is None
    txt = txt or []
    rec["txt"] = txt
    has_mail = bool(rec["mx"])
    sev_missing = "Medium" if (has_mail or rec["a"]) else "Low"
    fs = []

    # DMARC
    dtxt = _txt(res, f"_dmarc.{domain}")
    dm = [t for t in (dtxt or []) if t.lower().startswith("v=dmarc1")]
    rec["dmarc"] = dm[0] if dm else None
    if dtxt is None:
        rec["dmarc_lookup_failed"] = True
    elif not dm:
        fs.append(make(domain, domain, "DMARC", "dmarc_missing", severity=sev_missing, evidence="No _dmarc TXT record"))
    else:
        t = _tags(dm[0])
        p = t.get("p", "none").lower()
        ev = dm[0]
        if p == "none":
            fs.append(make(domain, domain, "DMARC", "dmarc_none", evidence=ev))
        if t.get("sp", p).lower() == "none" or (p in ("quarantine", "reject") and t.get("sp", "").lower() == "none"):
            fs.append(make(domain, domain, "DMARC", "dmarc_sp", evidence=ev))
        elif p == "none" and "sp" not in t:
            fs.append(make(domain, domain, "DMARC", "dmarc_sp", evidence=ev))
        if t.get("pct") and t["pct"].isdigit() and int(t["pct"]) < 100 and p != "none":
            fs.append(make(domain, domain, "DMARC", "dmarc_pct", evidence=ev))
        if "rua" not in t:
            fs.append(make(domain, domain, "DMARC", "dmarc_norua", evidence=ev))

    # SPF
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    rec["spf"] = spf[0] if spf else None
    if txt_failed:
        rec["spf_lookup_failed"] = True
    elif not spf:
        fs.append(make(domain, domain, "SPF", "spf_missing", severity=sev_missing, evidence="No v=spf1 TXT record"))
    else:
        s = spf[0].lower()
        if re.search(r"\s\+all\b|\s\?all\b", s) or not re.search(r"[-~+?]all\b|redirect=", s):
            fs.append(make(domain, domain, "SPF", "spf_weak", evidence=spf[0]))
        n = _spf_lookups(res, spf[0])
        rec["spf_lookups"] = n
        if n > 10:
            fs.append(make(domain, domain, "SPF", "spf_lookups", evidence=f"{n} lookups"))

    # DKIM (informational: selectors found)
    found = [s for s in DKIM_SELECTORS if _txt(res, f"{s}._domainkey.{domain}") or query(res, f"{s}._domainkey.{domain}", "CNAME")]
    rec["dkim_selectors"] = found

    # Zone transfer
    rec["axfr"] = {}
    for ns in rec["ns"]:
        z = _axfr(ns, domain)
        if z:
            rec["axfr"][ns] = z[:200]
            fs.append(make(domain, domain, "DNS", "zone_transfer", evidence=f"{ns} returned {len(z)} names", severity="High"))
    return rec, fs


def run(ctx):
    if ctx.cached("dns_records"):
        return
    log(f"DNS/email records for {len(ctx.roots)} domains")
    out = pmap(lambda d: analyze(ctx, d), ctx.roots, workers=min(8, ctx.workers))
    ctx.save("dns_records", {r["domain"]: r for r, _ in out})
    for _, fs in out:
        ctx.add(*fs)
