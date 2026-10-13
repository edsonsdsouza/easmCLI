"""Stage: subdomain + email enumeration and resolution."""
import re

from ..findings import make
from ..resolver import make_resolver, nxdomain, query
from ..util import have, log, norm_domain, pmap, retry_json, root_of, run as run_cmd, http_get

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def crtsh(domain):
    data = retry_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=60) or []
    hosts = set()
    for row in data:
        for n in row.get("name_value", "").split("\n"):
            hosts.add(norm_domain(n))
    return hosts


def hackertarget(domain):
    try:
        t = http_get(f"https://api.hackertarget.com/hostsearch/?q={domain}").text
        if "API count exceeded" in t or "error" in t.lower()[:30]:
            return set()
        return {norm_domain(l.split(",")[0]) for l in t.splitlines() if "," in l}
    except Exception:
        return set()


def otx(domain):
    d = retry_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns") or {}
    return {norm_domain(r.get("hostname", "")) for r in d.get("passive_dns", []) if r.get("hostname")}


def subfinder(ctx, domain):
    if not have("subfinder"):
        return set()
    _, out = run_cmd(["subfinder", "-silent", "-d", domain, "-r", ",".join(ctx.resolvers)], timeout=600, outfile=ctx.raw(f"subfinder-{domain}.txt"))
    return {norm_domain(l) for l in out.splitlines() if l.strip()}


def theharvester(ctx, domain):
    exe = "theHarvester" if have("theHarvester") else ("theharvester" if have("theharvester") else None)
    if not exe:
        return set(), set()
    _, out = run_cmd([exe, "-b", ctx.theharvester_sources, "-d", domain], timeout=1500,
                     outfile=ctx.raw(f"theharvester-{domain}.txt"))
    emails = {e.lower() for e in EMAIL_RE.findall(out) if e.lower().endswith("@" + domain) or e.lower().endswith("." + domain)}
    hosts = set()
    for line in out.splitlines():
        m = re.match(r"^\s*([a-z0-9._-]+\." + re.escape(domain) + r")(?::[\d.]+)?\s*$", line.strip().lower())
        if m:
            hosts.add(m.group(1))
    return hosts, emails


def dnsrecon(ctx, domain):
    if not have("dnsrecon"):
        return set()
    import json
    jf = ctx.raw(f"dnsrecon-{domain}.json")
    for ns in ctx.resolvers[:1]:
        run_cmd(["dnsrecon", "-d", domain, "-n", ns, "-a", "-y", "-z", "-j", jf], timeout=900,
                outfile=ctx.raw(f"dnsrecon-{domain}.txt"))
    hosts = set()
    try:
        for r in json.load(open(jf)):
            n = r.get("name") or r.get("target") or ""
            if n and re.search(r"[a-z]", n):
                hosts.add(norm_domain(n))
    except Exception:
        pass
    return hosts


def enumerate_domain(ctx, domain):
    hosts, emails, sources = set(), set(), {}
    for name, fn in (("crt.sh", crtsh), ("hackertarget", hackertarget), ("otx", otx)):
        try:
            h = fn(domain)
        except Exception:
            h = set()
        sources[name] = len(h)
        hosts |= h
    h = subfinder(ctx, domain); sources["subfinder"] = len(h); hosts |= h
    h, e = theharvester(ctx, domain); sources["theHarvester"] = len(h); hosts |= h; emails |= e
    h = dnsrecon(ctx, domain); sources["dnsrecon"] = len(h); hosts |= h
    hosts.add(domain)
    hosts = {h for h in hosts if (h == domain or h.endswith("." + domain)) and "*" not in h and " " not in h and not ctx.excluded(h)}
    log(f"{domain}: {len(hosts)} candidate hosts {sources}")
    return domain, hosts, emails, sources


def resolve_host(ctx, host):
    res = make_resolver(ctx.resolvers)
    a = query(res, host, "A") or []
    aaaa = query(res, host, "AAAA") or []
    cname = [c.rstrip(".") for c in (query(res, host, "CNAME") or [])]
    return host, {"ips": a, "ipv6": aaaa, "cname": cname}


def run(ctx):
    if ctx.cached("subdomains"):
        return
    results = pmap(lambda d: enumerate_domain(ctx, d), ctx.roots, workers=min(4, ctx.workers))
    all_hosts, emails, src = {}, {}, {}
    for d, hosts, em, s in results:
        src[d] = s
        for h in hosts:
            all_hosts[h] = d
        for e in em:
            emails[e] = d
    names = sorted(all_hosts)
    log(f"Resolving {len(names)} hosts")
    resolved = dict(pmap(lambda h: resolve_host(ctx, h), names, workers=ctx.workers))
    hosts = {}
    res = make_resolver(ctx.resolvers)
    for h in names:
        r = resolved[h]
        r["root"] = all_hosts[h]
        r["resolves"] = bool(r["ips"] or r["ipv6"])
        hosts[h] = r
        # dangling CNAME => possible takeover
        if r["cname"] and not r["resolves"]:
            tgt = r["cname"][0]
            if nxdomain(res, tgt):
                ctx.add(make(all_hosts[h], h, "DNS", "dangling_cname", evidence=f"{h} -> {tgt} (NXDOMAIN)"))
    ctx.save("subdomains", {"hosts": hosts, "emails": emails, "sources": src})
