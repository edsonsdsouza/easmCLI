import argparse
import datetime as dt
import glob
import os
import sys

from . import __version__
from .context import Ctx
from .diff import compare
from .findings import from_dict
from .stages import dns_records, discovery, leaks, liveness, ports, subdomains, webchecks
from .util import have, jload, jsave, log, use_public_dns

SKIPPABLE = ["discovery", "dns", "ports", "web", "leaks"]
TOOLS = {"nmap": "port/service scan (required for the ports stage)", "nuclei": "deeper misconfiguration/exposure checks",
         "subfinder": "extra subdomain source", "theHarvester": "emails + subdomains (your original step)",
         "dnsrecon": "DNS records / brute (your original step)", "dnstwist": "better look-alike domain generation"}


def banner():
    log("Only run against assets you are authorized to test.", "!")


def _split(vals):
    out = []
    for v in vals or []:
        out += [x for x in v.replace(",", " ").split() if x]
    return out


def _last_run(out_root):
    runs = sorted(glob.glob(os.path.join(out_root, "*", "inputs.json")) + glob.glob(os.path.join(out_root, "inputs.json")))
    runs = sorted(runs, key=os.path.getmtime)
    return os.path.dirname(runs[-1]) if runs else None


def cmd_run(a):
    banner()
    roots = _split(a.domain)
    if a.domains_file:
        roots += [l.strip() for l in open(a.domains_file) if l.strip() and not l.startswith("#")]
    keywords, excludes, org = _split(a.keyword), _split(a.exclude), a.org
    skip = set(_split(a.skip))
    prev = None
    if a.repeat:
        src = _last_run(a.out_root) if a.repeat == "last" else a.repeat
        inp = jload(os.path.join(src, "inputs.json")) if src else None
        if not inp:
            raise SystemExit(f"No previous run found for --repeat {a.repeat}")
        roots = sorted(set(roots) | set(inp["roots"]))
        keywords = sorted(set(keywords) | set(inp.get("keywords", [])))
        excludes = sorted(set(excludes) | set(inp.get("excludes", [])))
        org = org or inp.get("org", "")
        prev = os.path.join(src, "findings.json")
        log(f"Repeating inputs from {src}")
    if not roots and not keywords:
        raise SystemExit("Give at least one -d domain (or --domains-file / --repeat).")
    if a.diff:
        prev = os.path.join(a.diff, "findings.json")
    elif prev is None and not a.no_diff:
        last = _last_run(a.out_root)
        prev = os.path.join(last, "findings.json") if last else None
    label = (org or (roots[0] if roots else keywords[0])).lower().replace(" ", "_")
    outdir = a.resume or os.path.join(a.out_root, label + "_" + dt.datetime.now().strftime("%Y-%m-%d_%H%M"))
    ctx = Ctx(roots, keywords, excludes, org, outdir, resume=bool(a.resume), skip=skip, top_ports=a.top_ports,
              workers=a.workers, resolvers=a.resolver or None, include_discovered=a.include_discovered,
              theharvester_sources=a.theharvester_sources, nmap_parallel=a.nmap_parallel)
    jsave(os.path.join(outdir, "inputs.json"), ctx.inputs())
    use_public_dns(ctx.resolvers)
    log(f"Run folder: {outdir}")
    pipeline(ctx, prev)
    return 0


def pipeline(ctx, prev):
    steps = [("discovery", discovery.run), ("dns", dns_records.run), ("subdomains", subdomains.run),
             ("liveness", liveness.run), ("ports", ports.run), ("web", webchecks.run), ("leaks", leaks.run)]
    for name, fn in steps:
        if name in ctx.skip:
            log(f"skipping {name}")
            continue
        if name in ("web", "ports") and "liveness" not in ctx.data:
            continue
        log(f"=== {name} ===")
        fn(ctx)
    # NOTE: findings are rebuilt from scratch on resume only for stages that re-run; persist all findings
    finish(ctx, prev)


def finish(ctx, prev):
    if ctx.resume:  # cached stages don't re-emit findings -> reuse saved ones
        saved = jload(os.path.join(ctx.outdir, "findings.json"), [])
        have_keys = {f.key for f in ctx.findings}
        ctx.findings += [from_dict(x) for x in saved if x["key"] not in have_keys]
    seen, uniq = set(), []
    for f in ctx.findings:
        if f.key not in seen:
            seen.add(f.key); uniq.append(f)
    ctx.findings = uniq
    fixed = compare(ctx, prev)
    jsave(os.path.join(ctx.outdir, "findings.json"), [f.to_dict() for f in ctx.findings])
    jsave(os.path.join(ctx.outdir, "fixed.json"), fixed)
    from .report import build
    path = os.path.join(ctx.outdir, f"EASM_Report_{dt.datetime.now():%b-%Y}.xlsx")
    build(ctx, fixed, path)
    sev = {}
    for f in ctx.findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    new = sum(1 for f in ctx.findings if f.extra.get("status") == "New")
    log(f"Done. {len(ctx.findings)} findings {sev}; new={new}; fixed={len(fixed)}")
    log(f"Report: {path}")


def cmd_report(a):
    """Rebuild the xlsx from a finished run folder (e.g. after editing raw data or upgrading easm)."""
    inp = jload(os.path.join(a.run_dir, "inputs.json"))
    if not inp:
        raise SystemExit("Not an easm run folder (inputs.json missing)")
    ctx = Ctx(inp["roots"], inp.get("keywords", []), inp.get("excludes", []), inp.get("org", ""), a.run_dir, skip=inp.get("skip", []))
    for p in glob.glob(os.path.join(a.run_dir, "data", "*.json")):
        ctx.data[os.path.basename(p)[:-5]] = jload(p)
    ctx.findings = [from_dict(x) for x in jload(os.path.join(a.run_dir, "findings.json"), [])]
    fixed = jload(os.path.join(a.run_dir, "fixed.json"), [])
    from .report import build
    out = os.path.join(a.run_dir, f"EASM_Report_{dt.datetime.now():%b-%Y}.xlsx")
    build(ctx, fixed, out)
    log(f"Report: {out}")
    return 0


def cmd_doctor(a):
    ok = True
    print(f"easm {__version__} - environment check\n")
    for t, why in TOOLS.items():
        found = have(t) or (t == "theHarvester" and have("theharvester"))
        print(f"  [{'x' if found else ' '}] {t:<13} {why}")
    print(f"  [{'x' if os.environ.get('HIBP_KEY') else ' '}] HIBP_KEY      leaked-credentials stage (env var)")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("\n  note: not root - nmap OS detection (-O) will be skipped; run with sudo for full parity.")
    print("\nMissing tools are skipped gracefully; the native checks (DNS, headers, TLS, liveness) always run.")
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="easm", description="External Attack Surface Monitoring")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run the full monthly activity")
    r.add_argument("-d", "--domain", action="append", help="root domain (repeatable, or comma-separated)")
    r.add_argument("-k", "--keyword", action="append", help="org keyword for discovering other domains (repeatable)")
    r.add_argument("--domains-file", help="file with one domain per line")
    r.add_argument("--exclude", action="append", help="domain/subdomain to leave out (repeatable)")
    r.add_argument("--org", default="", help="organization name for the report")
    r.add_argument("--out-root", default="easm-runs", help="folder holding all runs (default: easm-runs)")
    r.add_argument("--repeat", metavar="last|RUN_DIR", help="reuse inputs of a previous run")
    r.add_argument("--diff", metavar="RUN_DIR", help="compare against this run (default: previous run in out-root)")
    r.add_argument("--no-diff", action="store_true")
    r.add_argument("--resume", metavar="RUN_DIR", help="continue an interrupted run, reusing finished stages")
    r.add_argument("--skip", action="append", help=f"stages to skip: {', '.join(SKIPPABLE)}")
    r.add_argument("--include-discovered", action="store_true", help="also scan keyword-discovered domains (review first!)")
    r.add_argument("--top-ports", type=int, default=2000)
    r.add_argument("--workers", type=int, default=20)
    r.add_argument("--nmap-parallel", type=int, default=2)
    r.add_argument("--resolver", action="append", help="DNS resolver (default 8.8.8.8, 1.1.1.1)")
    r.add_argument("--theharvester-sources", default="all", help="-b value for theHarvester (default: all)")
    r.set_defaults(fn=cmd_run)

    rp = sub.add_parser("report", help="rebuild the xlsx from a run folder")
    rp.add_argument("run_dir")
    rp.set_defaults(fn=cmd_report)

    dr = sub.add_parser("doctor", help="check which external tools/keys are available")
    dr.set_defaults(fn=cmd_doctor)

    a = p.parse_args(argv)
    sys.exit(a.fn(a))


if __name__ == "__main__":
    main()
