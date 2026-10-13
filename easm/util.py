import ipaddress, json, os, re, shutil, socket, subprocess, sys, time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests

UA = "easm/0.1 (authorized external attack surface monitoring)"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


def log(msg, level="*"):
    print(f"[{level}] {msg}", file=sys.stderr, flush=True)


def have(tool):
    return shutil.which(tool) is not None


def run(cmd, timeout=1800, outfile=None):
    """Run an external command; return (rc, stdout). Never raises."""
    log("$ " + " ".join(cmd), ">")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = p.stdout
        if outfile:
            with open(outfile, "w") as f:
                f.write(out + ("\n" + p.stderr if p.stderr else ""))
        return p.returncode, out
    except subprocess.TimeoutExpired:
        log(f"timeout: {cmd[0]}", "!")
    except FileNotFoundError:
        log(f"not installed: {cmd[0]}", "!")
    except Exception as e:  # noqa
        log(f"{cmd[0]} failed: {e}", "!")
    return -1, ""


def jsave(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)


def jload(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def norm_domain(d):
    d = d.strip().lower().rstrip(".")
    d = re.sub(r"^https?://", "", d).split("/")[0].split(":")[0]
    if d.startswith("*."):
        d = d[2:]
    return d


def valid_domain(d):
    return bool(_DOMAIN_RE.match(d))


def root_of(host, roots):
    """Return the in-scope root domain a host belongs to (longest match)."""
    host = host.lower()
    best = None
    for r in roots:
        if host == r or host.endswith("." + r):
            if best is None or len(r) > len(best):
                best = r
    return best


def pmap(fn, items, workers=20):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))


def http_get(url, **kw):
    kw.setdefault("timeout", 20)
    kw.setdefault("headers", {"User-Agent": UA})
    return requests.get(url, **kw)


def retry_json(url, tries=3, **kw):
    for i in range(tries):
        try:
            r = http_get(url, **kw)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (429, 502, 503, 504):
                time.sleep(3 * (i + 1))
                continue
            return None
        except Exception:
            time.sleep(2 * (i + 1))
    return None


_orig_getaddrinfo = socket.getaddrinfo


def use_public_dns(resolvers):
    """Force every hostname lookup in this process (requests, ssl, sockets) through public resolvers,
    so probes see what an outside attacker sees, never internal/split-horizon DNS.
    A name with no public answer fails to resolve - exactly as it would externally.
    Proxy hosts and localhost are left alone so a corporate proxy still works."""
    from . import resolver as R
    res = R.make_resolver(resolvers)
    keep = {"localhost"}
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        v = os.environ.get(var)
        if v:
            h = urlparse(v if "//" in v else "//" + v).hostname
            if h:
                keep.add(h)

    def gai(host, port, family=0, type=0, proto=0, flags=0):
        if isinstance(host, bytes):
            host = host.decode()
        if not host or host in keep:
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
        try:
            ipaddress.ip_address(host)
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
        except ValueError:
            pass
        ips = []
        if family in (0, socket.AF_INET):
            ips += R.query(res, host, "A") or []
        if family in (0, socket.AF_INET6):
            ips += R.query(res, host, "AAAA") or []
        if not ips:
            raise socket.gaierror(socket.EAI_NONAME, f"no public DNS answer for {host}")
        out = []
        for ip in ips:
            out += _orig_getaddrinfo(ip, port, family, type, proto, flags | socket.AI_NUMERICHOST)
        return out

    socket.getaddrinfo = gai
    log(f"All lookups forced through public DNS: {', '.join(resolvers)}")
