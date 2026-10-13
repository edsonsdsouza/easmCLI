import dns.exception
import dns.resolver

_cache = {}


def make_resolver(nameservers, timeout=4):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(nameservers)
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def query(res, name, rtype):
    """Return list of answers; [] when the record definitively does not exist (NXDOMAIN/NoAnswer);
    None when the lookup FAILED (timeout, SERVFAIL, no network) - callers must not treat that as 'missing'."""
    key = (id(res), name, rtype)
    if key in _cache:
        return _cache[key]
    try:
        ans = [a.to_text() for a in res.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        ans = []
    except Exception:
        ans = None
    _cache[key] = ans
    return ans


def nxdomain(res, name):
    try:
        res.resolve(name, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False
