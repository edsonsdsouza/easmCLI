"""Stage: nmap service scan, once per unique public IP of live hosts."""
import ipaddress
import os
import xml.etree.ElementTree as ET

from ..findings import RISKY_PORTS, make
from ..util import have, log, pmap, run as run_cmd


def parse_xml(path):
    ports = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return ports
    for h in root.findall("host"):
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            ports.append({"port": int(p.get("portid")), "proto": p.get("protocol"),
                          "service": sv.get("name", "") if sv is not None else "",
                          "product": sv.get("product", "") if sv is not None else "",
                          "version": sv.get("version", "") if sv is not None else "",
                          "extrainfo": sv.get("extrainfo", "") if sv is not None else ""})
    return ports


def scan_ip(ctx, ip):
    base = ctx.raw(f"nmap-{ip.replace(':', '_')}")
    cmd = ["nmap", "--top-ports", str(ctx.top_ports), "-sV", "-sC", "-v", "-oN", base + ".txt", "-oX", base + ".xml", "--dns-servers", ctx.resolvers[0]]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd.insert(5, "-O")  # OS detection needs root
    run_cmd(cmd + [ip], timeout=3600)
    return ip, parse_xml(base + ".xml")


def run(ctx):
    if ctx.cached("ports"):
        return
    if not have("nmap"):
        log("nmap not installed - skipping port scan (run `easm doctor`)", "!")
        ctx.save("ports", {"skipped": True, "ips": {}})
        return
    hosts = ctx.data["subdomains"]["hosts"]
    live_hosts = {r["host"] for r in ctx.data["liveness"]}
    # scan live hosts plus root domains that resolve (they may run non-web services like mail/VPN)
    targets = live_hosts | {h for h in hosts if h in ctx.roots and hosts[h]["resolves"]}
    ip_hosts = {}
    for h in targets:
        for ip in hosts[h]["ips"]:
            try:
                if ipaddress.ip_address(ip).is_global:
                    ip_hosts.setdefault(ip, []).append(h)
            except ValueError:
                pass
    log(f"nmap: {len(ip_hosts)} unique public IPs")
    res = dict(pmap(lambda ip: scan_ip(ctx, ip), sorted(ip_hosts), workers=ctx.nmap_parallel))
    out = {"skipped": False, "ips": {}}
    for ip, ports in res.items():
        out["ips"][ip] = {"hosts": sorted(ip_hosts[ip]), "ports": ports}
        for p in ports:
            if p["port"] in RISKY_PORTS:
                h = sorted(ip_hosts[ip])[0]
                root = hosts[h]["root"]
                svc = RISKY_PORTS[p["port"]]
                ctx.add(make(root, h, "Ports", "risky_port", name=f"{svc} Exposed To Internet ({p['port']}/{p['proto']})",
                             port=str(p["port"]), url=f"{ip}:{p['port']}",
                             evidence=f"{ip}:{p['port']} {p['product']} {p['version']}".strip(),
                             severity="High", extra={"id": ip}))
    ctx.save("ports", out)
