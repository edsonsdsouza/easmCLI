"""Stage: breached credentials via HaveIBeenPwned domain search (needs HIBP_KEY + verified domain)."""
import os
import time

import requests

from ..findings import make
from ..util import UA, log


def run(ctx):
    key = os.environ.get("HIBP_KEY")
    if ctx.cached("leaks"):
        return
    if not key:
        log("HIBP_KEY not set - skipping leaked-credentials stage", "!")
        ctx.save("leaks", {"skipped": True, "rows": []})
        return
    H = {"hibp-api-key": key, "user-agent": UA}
    meta, rows = {}, []
    for d in ctx.roots:
        try:
            r = requests.get(f"https://haveibeenpwned.com/api/v3/breacheddomain/{d}", headers=H, timeout=30)
        except Exception as e:
            log(f"HIBP {d}: {e}", "!"); continue
        if r.status_code != 200:
            log(f"HIBP {d}: HTTP {r.status_code} (domain must be verified in your HIBP dashboard)", "!")
            time.sleep(7); continue
        for alias, breaches in r.json().items():
            email = f"{alias}@{d}"
            for b in breaches:
                if b not in meta:
                    try:
                        meta[b] = requests.get(f"https://haveibeenpwned.com/api/v3/breach/{b}", headers=H, timeout=30).json()
                    except Exception:
                        meta[b] = {}
                    time.sleep(7)
                m = meta[b]
                rows.append({"domain": d, "leak": b, "description": (m.get("Description") or "").replace("<a ", "").split("<")[0][:400],
                             "date": m.get("BreachDate", ""), "classes": ", ".join(m.get("DataClasses", [])), "email": email})
                ctx.add(make(d, d, "Leaks", "leak", name=f"Credentials in breach: {b}", evidence=email,
                             extra={"id": email + b}, description=f"{email} found in the {b} breach ({m.get('BreachDate','')}). Data: {', '.join(m.get('DataClasses', []))}"))
        time.sleep(7)
    ctx.save("leaks", {"skipped": False, "rows": rows})
