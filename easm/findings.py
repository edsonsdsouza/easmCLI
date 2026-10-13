import hashlib
from dataclasses import dataclass, asdict, field

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# check id -> (name, description, remediation, reference, default severity)
KB = {
    "dmarc_missing": ("DMARC Record Missing", "No DMARC record was found, so receivers cannot be told how to handle spoofed mail from this domain.",
        "Publish a TXT record at _dmarc.<domain>, start with p=none and rua reporting, then move to quarantine/reject.", "https://dmarc.org/overview/", "Medium"),
    "dmarc_none": ("DMARC Policy Not Enforced (p=none)", "DMARC exists but policy is p=none, so spoofed mail is still delivered.",
        "Enforce the policy: move to p=quarantine and then p=reject after reviewing aggregate reports.", "https://dmarc.org/overview/", "Medium"),
    "dmarc_sp": ("DMARC Subdomain Policy Not Strict", "The subdomain policy (sp=) is weaker than the domain policy or missing while p=none.",
        "Set sp=reject (or quarantine) so subdomains get the same protection as the apex domain.", "https://dmarc.org/overview/", "Low"),
    "dmarc_pct": ("DMARC Applied To Partial Mail (pct<100)", "pct is below 100 so only part of failing mail is subject to policy.",
        "Raise pct to 100 once reports show legitimate mail passes.", "https://dmarc.org/overview/", "Low"),
    "dmarc_norua": ("DMARC Reporting Not Configured", "No rua= tag, so aggregate reports are not received.",
        "Add rua=mailto:<mailbox> to receive aggregate reports.", "https://dmarc.org/overview/", "Low"),
    "spf_missing": ("SPF Record Missing", "A domain that sends or receives mail has no SPF record.",
        "Publish an SPF TXT record listing authorized senders, ending in -all (or ~all while testing).", "https://www.rfc-editor.org/rfc/rfc7208", "Medium"),
    "spf_weak": ("SPF Policy Too Permissive", "SPF ends in +all/?all or lacks an all mechanism.",
        "End the record with -all (or ~all) and remove broad mechanisms.", "https://www.rfc-editor.org/rfc/rfc7208", "Medium"),
    "spf_lookups": ("SPF Exceeds 10 DNS Lookups", "SPF evaluation will return PermError above 10 lookups.",
        "Flatten includes or remove unused senders.", "https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4", "Low"),
    "zone_transfer": ("DNS Zone Transfer Allowed", "A name server answered an AXFR request, exposing the full zone.",
        "Restrict AXFR to authorized secondary servers only.", "https://owasp.org/www-community/attacks/DNS_Zone_Transfer", "High"),
    "dangling_cname": ("Possible Subdomain Takeover (Dangling CNAME)", "CNAME target does not resolve, so it may be claimable by a third party.",
        "Remove the stale CNAME or re-provision the target resource.", "https://owasp.org/www-project-web-security-testing-guide/", "High"),
    "tls_expired": ("Expired SSL Certificate", "The certificate presented has expired, causing browser warnings and breaking trust.",
        "Renew the certificate and automate renewal.", "https://www.acunetix.com/vulnerabilities/web/ssl-certificate-expired/", "Low"),
    "tls_expiring": ("SSL Certificate Expiring Soon", "The certificate expires in under 30 days.",
        "Renew the certificate and automate renewal.", "https://letsencrypt.org/docs/", "Low"),
    "tls_mismatch": ("SSL Certificate Name Mismatch", "The certificate does not cover the hostname.",
        "Issue a certificate that includes this hostname.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security", "Medium"),
    "tls_selfsigned": ("Self-Signed / Untrusted Certificate", "The certificate chain is not trusted by a public CA.",
        "Use a certificate from a trusted CA.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security", "Medium"),
    "tls_old_proto": ("Deprecated TLS Protocol Supported", "Server accepts TLS 1.0/1.1.",
        "Disable TLS 1.0/1.1 and allow only TLS 1.2+.", "https://datatracker.ietf.org/doc/rfc8996/", "Medium"),
    "hdr_csp": ("Content Security Policy (CSP) Header Not Implemented", "CSP is missing, which reduces protection against XSS and data injection.",
        "Implement a Content-Security-Policy header.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "Medium"),
    "hdr_hsts": ("Strict-Transport-Security Header Not Implemented", "HSTS is missing on an HTTPS site.",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "Low"),
    "hdr_xcto": ("X-Content-Type-Options Header Not Implemented", "Browser MIME sniffing is not disabled.",
        "Set X-Content-Type-Options: nosniff.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options", "Low"),
    "hdr_xfo": ("Clickjacking Protection Missing (X-Frame-Options / frame-ancestors)", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
        "Set X-Frame-Options: SAMEORIGIN or CSP frame-ancestors 'self'.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options", "Low"),
    "hdr_refpol": ("Referrer-Policy Header Not Implemented", "Referrer information may leak to third parties.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter).", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy", "Info"),
    "hdr_server": ("Server Version Disclosure", "The Server/X-Powered-By header reveals product or version.",
        "Suppress or genericize version banners.", "https://owasp.org/www-project-web-security-testing-guide/", "Info"),
    "cookie_httponly": ("Cookie Without HttpOnly Attribute", "Cookies lack HttpOnly and can be read by scripts.",
        "Set HttpOnly on session cookies.", "https://owasp.org/www-community/HttpOnly", "Low"),
    "cookie_secure": ("Cookie Without Secure Attribute", "Cookies lack Secure and can be sent over HTTP.",
        "Set Secure on cookies served over HTTPS.", "https://owasp.org/www-community/controls/SecureCookieAttribute", "Low"),
    "http_no_redirect": ("HTTP Not Redirected To HTTPS", "The site serves content over plain HTTP without redirecting.",
        "Redirect all HTTP traffic to HTTPS.", "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security", "Low"),
    "risky_port": ("Risky Service Exposed To Internet", "A administrative or database service is reachable from the internet.",
        "Restrict the service to VPN/allow-listed IPs or close the port.", "https://www.cisecurity.org/controls", "High"),
    "leak": ("Credentials Found In Public Breach", "Email addresses of this domain appear in a known breach.",
        "Force password resets, enable MFA, and review reuse.", "https://haveibeenpwned.com/", "Medium"),
    "similar_domain": ("Similar (Look-alike) Domain Registered", "A look-alike domain resolves and may be used for phishing or brand abuse.",
        "Verify ownership; if third-party, consider takedown or monitoring.", "https://owasp.org/www-community/attacks/Typosquatting", "Info"),
}

RISKY_PORTS = {21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
               5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB",
               11211: "Memcached", 2375: "Docker API", 5984: "CouchDB", 1521: "Oracle", 389: "LDAP", 139: "NetBIOS"}


@dataclass
class Finding:
    domain: str           # in-scope root domain
    host: str             # host/subdomain affected
    category: str         # DMARC | SPF | DNS | SSL | Headers | Misconfiguration | Ports | Leaks | Similar
    check: str            # KB id
    name: str = ""
    description: str = ""
    remediation: str = ""
    reference: str = ""
    severity: str = "Info"
    port: str = ""
    url: str = ""
    evidence: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def key(self):
        raw = "|".join([self.domain, self.host, self.check, self.port, self.name, self.extra.get("id", "")])
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def to_dict(self):
        d = asdict(self)
        d["key"] = self.key
        return d


def make(domain, host, category, check, **kw):
    name, desc, rem, ref, sev = KB.get(check, (check, "", "", "", "Info"))
    f = Finding(domain=domain, host=host, category=category, check=check, name=kw.pop("name", name),
                description=kw.pop("description", desc), remediation=kw.pop("remediation", rem),
                reference=kw.pop("reference", ref), severity=kw.pop("severity", sev))
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def from_dict(d):
    d = dict(d)
    d.pop("key", None)
    return Finding(**d)
