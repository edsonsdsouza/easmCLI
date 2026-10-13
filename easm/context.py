import datetime as dt
import os

from .util import jload, jsave, log, norm_domain, valid_domain

DEFAULT_RESOLVERS = ["8.8.8.8", "1.1.1.1"]


class Ctx:
    def __init__(self, roots, keywords=(), excludes=(), org="", outdir=".", resume=False,
                 skip=(), top_ports=2000, workers=20, resolvers=None, include_discovered=False,
                 theharvester_sources="all", nmap_parallel=2):
        self.roots = sorted({norm_domain(d) for d in roots if d.strip()})
        bad = [d for d in self.roots if not valid_domain(d)]
        if bad:
            raise SystemExit(f"Invalid domain(s): {', '.join(bad)}")
        self.keywords = sorted({k.strip().lower() for k in keywords if k.strip()})
        self.excludes = {norm_domain(e) for e in excludes if e.strip()}
        self.roots = [r for r in self.roots if r not in self.excludes]
        self.org = org or (self.keywords[0].upper() if self.keywords else (self.roots[0] if self.roots else "Organization"))
        self.outdir = outdir
        self.resume = resume
        self.skip = set(skip)
        self.top_ports = top_ports
        self.workers = workers
        self.resolvers = resolvers or DEFAULT_RESOLVERS
        self.include_discovered = include_discovered
        self.theharvester_sources = theharvester_sources
        self.nmap_parallel = nmap_parallel
        self.started = dt.datetime.now()
        self.data = {}       # stage -> result
        self.findings = []   # list[Finding]
        os.makedirs(self.raw(), exist_ok=True)
        os.makedirs(os.path.join(outdir, "data"), exist_ok=True)

    # paths
    def raw(self, *p):
        return os.path.join(self.outdir, "raw", *p)

    def dpath(self, name):
        return os.path.join(self.outdir, "data", name + ".json")

    def excluded(self, host):
        return any(host == e or host.endswith("." + e) for e in self.excludes)

    # stage cache
    def cached(self, name):
        if self.resume:
            v = jload(self.dpath(name))
            if v is not None:
                log(f"{name}: using cached data (--resume)")
                self.data[name] = v
                return True
        return False

    def save(self, name, value):
        self.data[name] = value
        jsave(self.dpath(name), value)

    def add(self, *findings):
        self.findings.extend(findings)

    def inputs(self):
        return {"roots": self.roots, "keywords": self.keywords, "excludes": sorted(self.excludes), "org": self.org,
                "top_ports": self.top_ports, "resolvers": self.resolvers, "skip": sorted(self.skip)}
