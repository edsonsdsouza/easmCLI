from .util import jload

CATS_BY_STAGE = {"dns": {"DMARC", "SPF", "DNS"}, "web": {"Headers", "SSL", "Misconfiguration", "Other"},
                 "ports": {"Ports"}, "leaks": {"Leaks"}, "discovery": {"Similar"}}


def compare(ctx, prev_findings_path):
    """Annotate ctx.findings with status New/Open and return list of Fixed (previous findings no longer present)."""
    prev = jload(prev_findings_path) if prev_findings_path else None
    if prev is None:
        for f in ctx.findings:
            f.extra["status"] = "Open"
        return []
    prev_keys = {p["key"]: p for p in prev}
    cur = {f.key for f in ctx.findings}
    for f in ctx.findings:
        f.extra["status"] = "Open" if f.key in prev_keys else "New"
    # only call something Fixed if its stage actually ran this time
    skipped_cats = set()
    for st, cats in CATS_BY_STAGE.items():
        if st in ctx.skip:
            skipped_cats |= cats
    if ctx.data.get("ports", {}).get("skipped"):
        skipped_cats |= CATS_BY_STAGE["ports"]
    if ctx.data.get("leaks", {}).get("skipped"):
        skipped_cats |= CATS_BY_STAGE["leaks"]
    fixed = [p for p in prev if p["key"] not in cur and p["category"] not in skipped_cats and p["domain"] in ctx.roots]
    return fixed
