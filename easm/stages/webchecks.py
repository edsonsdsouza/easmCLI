"""Stage: security headers, cookie flags, TLS certificate/protocol checks (native), optional nuclei."""
import datetime as dt
import json
import socket
import ssl

from ..findings import make
from ..util import have, log, pmap, run as run_cmd

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
except Exception:  # cryptography is optional; TLS expiry checks degrade without it
    x509 = None


def header_findings(ctx, root, r):
    h, host, url = r["headers"], r["host"], r["final_url"]
    out = []
    https = url.startswith("https://")
    if r["code"] >= 400 and r["code"] not in (401, 403):
        return out
    def add(check, **kw):
        out.append(make(root, host, "Headers", check, url=url, **kw))
    csp = h.get("content-security-policy", "")
    if not csp:
        add("hdr_csp")
    if https and "strict-transport-security" not in h:
        add("hdr_hsts")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        add("hdr_xcto")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        add("hdr_xfo")
    if "referrer-policy" not in h:
        add("hdr_refpol")
    srv = h.get("x-powered-by") or h.get("server", "")
    if any(c.isdigit() for c in srv):
        add("hdr_server", evidence=srv)
    for c in r.get("set_cookie", []):
        name = c.split("=", 1)[0]
        low = c.lower()
        if "httponly" not in low:
            add("cookie_httponly", evidence=name, extra={"id": name})
        if https and "secure" not in low:
            add("cookie_secure", evidence=name, extra={"id": name})
    return out


def tls_check(host, port=443):
    """Return dict: not_after, names, issuer, verify_error, old_protocols."""
    info = {"host": host, "port": port}
    # 1) trust/hostname verification
    try:
        c = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                info["protocol"] = ss.version()
    except ssl.SSLCertVerificationError as e:
        info["verify_error"] = e.verify_message or str(e)
    except Exception as e:
        info["error"] = type(e).__name__
        return info
    # 2) read cert without verifying
    try:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as s:
            with c.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                info.setdefault("protocol", ss.version())
        if x509 and der:
            cert = x509.load_der_x509_certificate(der)
            info["not_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.isoformat()
            info["not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.isoformat()
            info["issuer"] = cert.issuer.rfc4514_string()
            info["subject"] = cert.subject.rfc4514_string()
            try:
                info["names"] = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
            except Exception:
                info["names"] = []
            info["self_signed"] = cert.issuer == cert.subject
    except Exception:
        pass
    # 3) deprecated protocols
    old = []
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.set_ciphers("ALL:@SECLEVEL=0")
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, port), timeout=6) as s:
                with c.wrap_socket(s, server_hostname=host):
                    old.append(name)
        except Exception:
            pass
    info["old_protocols"] = old
    return info


def tls_findings(root, host, t):
    out = []
    if "error" in t:
        return out
    ev = t.get("verify_error", "")
    na = t.get("not_after")
    url = f"https://{host}:{t['port']}"
    if na:
        left = (dt.datetime.fromisoformat(na) - dt.datetime.now(dt.timezone.utc)).days
        if left < 0:
            out.append(make(root, host, "SSL", "tls_expired", url=url, port=str(t["port"]), evidence=f"Expired {na[:10]}"))
        elif left < 30:
            out.append(make(root, host, "SSL", "tls_expiring", url=url, port=str(t["port"]), evidence=f"Expires {na[:10]} ({left}d)"))
    if "hostname mismatch" in ev.lower() or "doesn't match" in ev.lower():
        out.append(make(root, host, "SSL", "tls_mismatch", url=url, port=str(t["port"]), evidence=ev))
    elif "self-signed" in ev.lower() or "self signed" in ev.lower() or "unable to get local issuer" in ev.lower():
        out.append(make(root, host, "SSL", "tls_selfsigned", url=url, port=str(t["port"]), evidence=ev))
    if t.get("old_protocols"):
        out.append(make(root, host, "SSL", "tls_old_proto", url=url, port=str(t["port"]), evidence=", ".join(t["old_protocols"])))
    return out


def nuclei(ctx, urls):
    if not have("nuclei") or not urls:
        return []
    lf = ctx.raw("nuclei-targets.txt")
    open(lf, "w").write("\n".join(sorted(urls)))
    of = ctx.raw("nuclei.jsonl")
    rf = ctx.raw("resolvers.txt")
    open(rf, "w").write("\n".join(ctx.resolvers))
    run_cmd(["nuclei", "-l", lf, "-r", rf, "-tags", "misconfig,exposure,cors,takeover,ssl", "-severity", "low,medium,high,critical",
             "-jsonl", "-o", of, "-silent", "-rl", "50"], timeout=3600)
    out = []
    try:
        for line in open(of):
            out.append(json.loads(line))
    except Exception:
        pass
    return out


def run(ctx):
    if ctx.cached("webchecks"):
        return
    live = ctx.data["liveness"]
    hosts = ctx.data["subdomains"]["hosts"]
    # headers/cookies: use the final response of each host's best protocol (prefer https)
    best = {}
    for r in live:
        if r["host"] not in best or r["proto"] == "https":
            best[r["host"]] = r
    for h, r in best.items():
        ctx.add(*header_findings(ctx, hosts[h]["root"], r))
    # TLS
    tls_hosts = sorted({r["host"] for r in live if r["proto"] == "https"})
    log(f"TLS checks on {len(tls_hosts)} hosts")
    tls = pmap(lambda h: tls_check(h), tls_hosts, workers=min(15, ctx.workers))
    tls_map = {t["host"]: t for t in tls}
    for t in tls:
        ctx.add(*tls_findings(hosts[t["host"]]["root"], t["host"], t))
    # nuclei (optional)
    nres = nuclei(ctx, {r["final_url"] for r in best.values()} | {f"{r['proto']}://{r['host']}" for r in live})
    for n in nres:
        info = n.get("info", {})
        host = n.get("host", "").split("://")[-1].split(":")[0].split("/")[0]
        root = hosts.get(host, {}).get("root") or next((x for x in ctx.roots if host.endswith(x)), host)
        tags = info.get("tags") or []
        cat = "SSL" if "ssl" in tags else ("Misconfiguration" if ("misconfig" in tags or "cors" in tags) else "Other")
        ref = info.get("reference") or ""
        ctx.add(make(root, host, cat, n.get("template-id", "nuclei"),
                     name=info.get("name", n.get("template-id", "")), description=info.get("description", ""),
                     remediation=info.get("remediation", "Review and remediate per the referenced guidance."),
                     reference=ref if isinstance(ref, str) else "\n".join(ref),
                     severity=(info.get("severity", "info") or "info").capitalize(),
                     url=n.get("matched-at", ""), port=str(n.get("port", "")), evidence=n.get("template-id", ""),
                     extra={"id": n.get("template-id", "") + n.get("matched-at", "")}))
    ctx.save("webchecks", {"tls": tls_map, "nuclei_count": len(nres)})
