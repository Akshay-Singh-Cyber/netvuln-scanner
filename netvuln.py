#!/usr/bin/env python3
"""
NetVuln - Automated Network Vulnerability Scanner

Runs an Nmap service/version scan, maps each detected service to known CVEs
using the NIST NVD API, and produces a severity-ranked HTML + JSON report.

Only scan systems you own or have written permission to test.
"""

import argparse
import html
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HTML_TOP_N = 25  # CVEs shown per service in the HTML; JSON keeps all
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


# --------------------------------------------------------------------------- #
# 1. Scanning
# --------------------------------------------------------------------------- #
def validate_target(target):
    """Accept an IP, a CIDR range or a hostname; reject obviously bad input."""
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    if target and set(target) <= allowed and not target.startswith("-"):
        return target
    raise ValueError(f"Invalid target: {target!r}")


def run_nmap(target, ports, xml_out):
    """Run nmap with version detection and save XML output."""
    if not shutil.which("nmap"):
        sys.exit("[!] nmap is not installed or not in PATH.")
    cmd = ["nmap", "-sV", "--version-intensity", "5", "-T4", "-Pn",
           "-p", ports, "-oX", xml_out, target]
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"[!] nmap failed:\n{result.stderr}")
    return xml_out


def parse_nmap_xml(xml_path):
    """Parse nmap XML into a list of hosts with their open services."""
    root = ET.parse(xml_path).getroot()
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        addr = host.find("address").get("addr")
        hn = host.find("hostnames/hostname")
        name = hn.get("name") if hn is not None else ""
        entry = {"address": addr,
                 "hostname": name if name != addr else "",
                 "services": []}
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            svc = svc if svc is not None else ET.Element("service")
            cpes = [c.text for c in svc.findall("cpe") if c.text]
            entry["services"].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "name": svc.get("name", "unknown"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "cpes": cpes,
                "lookup": "not-run",
                "cves": [],
            })
        hosts.append(entry)
    return hosts


# --------------------------------------------------------------------------- #
# 2. CVE lookup (NIST NVD API 2.0)
# --------------------------------------------------------------------------- #
def cpe22_to_23(cpe):
    """Nmap emits CPE 2.2 (cpe:/a:vendor:product:ver); NVD wants CPE 2.3."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    parts = cpe.replace("cpe:/", "").split(":")
    parts += ["*"] * (11 - len(parts))
    return "cpe:2.3:" + ":".join(parts[:11])


class NVDClient:
    def __init__(self, api_key=None, max_results=20):
        self.api_key = api_key
        self.max_results = max_results
        # NVD rate limits: 5 req / 30 s without a key, 50 req / 30 s with one.
        self.delay = 0.7 if api_key else 6.5
        self._last = 0.0
        self.cache = {}

    def _get(self, params):
        key = urllib.parse.urlencode(sorted(params.items()))
        if key in self.cache:
            return self.cache[key]
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        req = urllib.request.Request(f"{NVD_URL}?{key}")
        if self.api_key:
            req.add_header("apiKey", self.api_key)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:  # NVD returns 404 for CPEs it doesn't know
                data = {"vulnerabilities": []}
            else:
                raise LookupError(f"NVD HTTP {exc.code}") from exc
        except Exception as exc:  # DNS, no internet, timeout...
            raise LookupError(str(exc)) from exc
        finally:
            self._last = time.time()
        self.cache[key] = data  # only successful responses are cached
        return data

    def reachable(self):
        """Quick connectivity check so we fail fast instead of per-service."""
        try:
            self._get({"resultsPerPage": 1, "cveId": "CVE-2011-2523"})
            return True
        except LookupError as exc:
            print(f"[!] Cannot reach NVD API ({exc}).")
            return False

    def lookup(self, service):
        """Return (status, cves). Status: ok | no-version | ambiguous | failed."""
        version = service["version"]
        if not version:
            return "no-version", []  # would produce thousands of false positives
        if "X" in version.upper().replace("0X", "") or " - " in version:
            return "ambiguous", []   # e.g. Samba "3.X - 4.X" is a range, not a version
        # Strategy 1: exact CPE match (most precise).
        # Strategy 2: keyword search — needed because Nmap's CPE vendor names don't
        # always match NVD's (e.g. Nmap "vsftpd:vsftpd" vs NVD "vsftpd_project:vsftpd").
        queries = []
        versioned = [c for c in service["cpes"] if c.count(":") >= 4]
        if versioned:
            queries.append(("cpe", {"virtualMatchString": cpe22_to_23(versioned[0])}))
        if service["product"]:
            # Drop generic words Nmap adds ("Apache httpd" -> "Apache") for better matches
            words = [w for w in service["product"].split() if w.lower() not in ("httpd", "smtpd", "ftpd", "server", "daemon")]
            queries.append(("keyword", {"keywordSearch": " ".join(words + [version])}))
        if not queries:
            return "no-version", []
        for method, params in queries:
            params["resultsPerPage"] = self.max_results
            try:
                data = self._get(params)
            except LookupError as exc:
                print(f"    [!] lookup failed: {exc}")
                return "failed", []
            vulns = data.get("vulnerabilities", [])
            if vulns:
                service["match_method"] = method
                service["total_cves"] = data.get("totalResults", len(vulns))
                return "ok", [parse_cve(v["cve"]) for v in vulns]
        return "ok", []


def parse_cve(cve):
    """Extract ID, best-available CVSS score/severity and description."""
    metrics = cve.get("metrics", {})
    score, severity, version = None, "UNKNOWN", ""
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        if metrics.get(key):
            m = metrics[key][0]
            score = m["cvssData"].get("baseScore")
            severity = m["cvssData"].get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
            version = ver
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": cve["id"], "score": score, "severity": severity.upper(),
            "cvss_version": version, "description": desc}


# --------------------------------------------------------------------------- #
# 3. Reporting
# --------------------------------------------------------------------------- #
def summarize(hosts):
    counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for h in hosts:
        for s in h["services"]:
            for c in s["cves"]:
                counts[c["severity"] if c["severity"] in counts else "UNKNOWN"] += 1
    return counts


def service_risk(service):
    return max((SEVERITY_ORDER.get(c["severity"], 0) for c in service["cves"]), default=0)


def write_html(hosts, target, path):
    counts = summarize(hosts)
    colors = {"CRITICAL": "#7b1fa2", "HIGH": "#c62828", "MEDIUM": "#ef6c00",
              "LOW": "#2e7d32", "UNKNOWN": "#616161", "NONE": "#616161"}
    e = html.escape
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "".join(
        f'<div class="card" style="border-color:{colors[k]}"><b style="color:{colors[k]}">{v}</b>{k}</div>'
        for k, v in counts.items())

    body = ""
    for h in hosts:
        body += f"<h2>{e(h['address'])} {e(h['hostname'])}</h2>"
        if not h["services"]:
            body += "<p>No open ports found.</p>"
            continue
        for s in sorted(h["services"], key=service_risk, reverse=True):
            label = f"{s['port']}/{s['protocol']} — {s['name']} {s['product']} {s['version']}".strip()
            body += f"<h3>{e(label)}</h3>"
            if not s["cves"]:
                note = {
                    "ok": "No known CVEs found for this version.",
                    "no-version": "Version not detected; CVE lookup skipped — verify manually.",
                    "ambiguous": "Only a version range was detected; CVE lookup skipped — verify manually.",
                    "failed": "<b style='color:#c62828'>CVE lookup FAILED (NVD unreachable) — results incomplete.</b>",
                    "not-run": "CVE lookup not run (--no-cve).",
                }.get(s.get("lookup"), "")
                body += f"<p class='muted'>{note}</p>"
                continue
            rows = "".join(
                f"<tr><td><a href='https://nvd.nist.gov/vuln/detail/{e(c['id'])}'>{e(c['id'])}</a></td>"
                f"<td><span class='sev' style='background:{colors.get(c['severity'], '#616161')}'>"
                f"{e(c['severity'])}</span></td>"
                f"<td>{c['score'] if c['score'] is not None else '-'} <span class='muted'>v{c['cvss_version']}</span></td>"
                f"<td>{e(c['description'][:220])}{'…' if len(c['description']) > 220 else ''}</td></tr>"
                for c in sorted(s["cves"], key=lambda c: c["score"] or 0, reverse=True)[:HTML_TOP_N])
            method = "exact CPE match" if s.get("match_method") == "cpe" else "keyword match — verify relevance"
            body += f"<p class='muted'>{len(s['cves'])} CVE(s) via {method}.</p>"
            body += ("<table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr>"
                     f"{rows}</table>")
            if len(s["cves"]) > HTML_TOP_N:
                body += f"<p class='muted'>+ {len(s['cves']) - HTML_TOP_N} lower-scored CVEs in the JSON report.</p>"
            if s.get("total_cves", 0) > len(s["cves"]):
                body += (f"<p class='muted'>NVD reports {s['total_cves']} total; only {len(s['cves'])} fetched "
                         f"(raise --max-cves).</p>")

    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>NetVuln report – {e(target)}</title><style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222}}
.cards{{display:flex;gap:1rem;margin:1rem 0}}.card{{border:2px solid;border-radius:8px;padding:.6rem 1rem;min-width:90px;text-align:center}}
.card b{{display:block;font-size:1.6rem}}table{{border-collapse:collapse;width:100%;margin-bottom:1rem;font-size:.9rem}}
th,td{{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}th{{background:#f4f4f4}}
.sev{{color:#fff;padding:2px 6px;border-radius:4px;font-size:.8rem}}.muted{{color:#777}}
</style></head><body>
<h1>Network Vulnerability Report</h1>
<p>Target: <b>{e(target)}</b> · Generated: {stamp} · Hosts up: {len(hosts)}</p>
<div class="cards">{cards}</div>{body}
<p class="muted">CVE data from NIST NVD. Matches are based on detected versions and may include false positives — verify before remediation.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Nmap + NVD automated vulnerability scanner")
    ap.add_argument("target", nargs="?", help="IP, CIDR range or hostname")
    ap.add_argument("-p", "--ports", default="1-1024", help="Port range (default 1-1024)")
    ap.add_argument("-o", "--output", default="report", help="Output file prefix")
    ap.add_argument("--from-xml", help="Skip scanning; parse an existing nmap XML file")
    ap.add_argument("--no-cve", action="store_true", help="Skip NVD lookup (offline mode)")
    ap.add_argument("--max-cves", type=int, default=2000, help="Max CVEs fetched per service (NVD max 2000)")
    args = ap.parse_args()

    if args.from_xml:
        xml_path, target = args.from_xml, args.target or args.from_xml
    elif args.target:
        target = validate_target(args.target)
        xml_path = run_nmap(target, args.ports, f"{args.output}.xml")
    else:
        ap.error("provide a target or --from-xml")

    hosts = parse_nmap_xml(xml_path)
    n_svc = sum(len(h["services"]) for h in hosts)
    print(f"[+] {len(hosts)} host(s) up, {n_svc} open service(s)")

    if not args.no_cve:
        nvd = NVDClient(api_key=os.environ.get("NVD_API_KEY"), max_results=args.max_cves)
        if not nvd.reachable():
            print("[!] Check the scanning machine's internet/DNS. Writing report without CVE data.")
            print(f"[!] Re-run later without rescanning:  python3 {sys.argv[0]} --from-xml {xml_path}")
            for h in hosts:
                for s in h["services"]:
                    s["lookup"] = "failed"
        else:
            for h in hosts:
                for s in h["services"]:
                    print(f"[*] CVE lookup: {h['address']}:{s['port']} {s['product']} {s['version']}")
                    s["lookup"], s["cves"] = nvd.lookup(s)
                    print(f"    -> {s['lookup']}, {len(s['cves'])} CVE(s)")
            failed = sum(s["lookup"] == "failed" for h in hosts for s in h["services"])
            if failed:
                print(f"[!] {failed} lookup(s) failed — report is incomplete.")

    with open(f"{args.output}.json", "w") as f:
        json.dump({"target": target, "hosts": hosts}, f, indent=2)
    write_html(hosts, target, f"{args.output}.html")

    counts = summarize(hosts)
    print("[+] Summary: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"[+] Reports written: {args.output}.html, {args.output}.json")


if __name__ == "__main__":
    main()
