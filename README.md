# NetVuln – Automated Network Vulnerability Scanner

A Python tool that automates network reconnaissance and vulnerability mapping:

1. **Scans** targets with Nmap service/version detection (`-sV`)
2. **Maps** each detected service version to known CVEs using the **NIST NVD API 2.0** (CPE-based matching)
3. **Reports** findings as a severity-ranked **HTML report** (CVSS v3.1 → v3.0 → v2 fallback) plus machine-readable **JSON**

> ⚠️ Only scan systems you own or have explicit written permission to test.

## Features
- Accepts a single IP, CIDR range (e.g. `192.168.56.0/24`) or hostname, with input validation
- Converts Nmap CPE 2.2 identifiers to CPE 2.3 for accurate NVD matching; falls back to keyword search
- Skips CVE lookup for services without a detected version (avoids false positives)
- Respects NVD rate limits, caches repeated lookups, supports an optional `NVD_API_KEY`
- Offline mode (`--no-cve`) and re-analysis of saved scans (`--from-xml`)
- No third-party Python dependencies (standard library only)

## Usage
```bash
# Requires nmap installed (apt install nmap)
python3 netvuln.py 192.168.56.101 -p 1-1024 -o metasploitable

# Faster CVE lookups with a free NVD API key
export NVD_API_KEY=your_key
python3 netvuln.py 192.168.56.0/24

# Re-analyse an existing scan
python3 netvuln.py --from-xml scan.xml -o report
```

## Results: Metasploitable 2 lab
Scanned in an isolated VirtualBox host-only network (`-p 1-10000`):

- **26** open services enumerated
- **240+ candidate CVEs** (18 critical, 85 high, 114 medium, 24 low)
- Detected the **vsftpd 2.3.4 backdoor (CVE-2011-2523)** via keyword fallback, after exact CPE matching missed it (Nmap vendor `vsftpd` vs NVD `vsftpd_project`)

![Sample report](screenshots/report.png)

### Limitations found during testing
- **False positives:** version-range matching includes CVEs for other platforms (e.g. Windows-only Apache `mod_isapi`) or other branches (Apache 2.4.x bugs listed against 2.2.8). Findings need manual triage.
- **False negatives:** services without a detected version (UnrealIRCd, the port-1524 bindshell) or with only a version range (Samba `3.X - 4.X`) cannot be matched to CVEs. Version matching alone misses backdoors and misconfigurations.

## History
Started in Feb 2024 as a simple single-port Nmap automation script; rebuilt in Nov 2026 into a full service-to-CVE vulnerability mapping tool.

## Roadmap
- Enrich findings with CISA KEV (Known Exploited Vulnerabilities) flags
- Diff two scans to show newly exposed services
