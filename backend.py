#!/usr/bin/env python3
"""
VulnScan Backend - Port Scanner + Vulnerability Checker
Uses nmap for scanning and NVD API for CVE lookups
"""

import json
import sys
import subprocess
import urllib.request
import urllib.parse
import time
import re
from typing import Optional


def run_nmap_scan(target: str) -> dict:
    """Run nmap scan and return parsed results"""
    print(f"[*] Starting nmap scan on: {target}", file=sys.stderr)
    
    try:
        # Run nmap with version detection and script scan
        cmd = [
            "nmap",
            "-sV",           # Version detection
            "--version-intensity", "5",
            "-sC",           # Default scripts
            "-T4",           # Aggressive timing
            "--open",        # Only show open ports
            "-p", "1-10000", # Port range
            "--script", "banner,http-title,ssl-cert",
            "-oX", "-",      # XML output to stdout
            target
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0 and not result.stdout:
            return {"error": f"nmap failed: {result.stderr}"}
        
        return parse_nmap_xml(result.stdout)
        
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 120 seconds"}
    except FileNotFoundError:
        return {"error": "nmap not found. Install with: sudo apt-get install nmap"}
    except Exception as e:
        return {"error": str(e)}


def parse_nmap_xml(xml_output: str) -> dict:
    """Parse nmap XML output into structured data"""
    import xml.etree.ElementTree as ET
    
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {"error": "Failed to parse nmap output"}
    
    results = {
        "scan_info": {},
        "hosts": []
    }
    
    # Get scan info
    runstats = root.find("runstats/finished")
    if runstats is not None:
        results["scan_info"]["elapsed"] = runstats.get("elapsed", "")
        results["scan_info"]["summary"] = runstats.get("summary", "")
    
    for host in root.findall("host"):
        host_data = {"ports": [], "os": None, "status": "unknown"}
        
        # Status
        status = host.find("status")
        if status is not None:
            host_data["status"] = status.get("state", "unknown")
        
        # Address
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4":
                host_data["ip"] = addr.get("addr", "")
            elif addr_type == "mac":
                host_data["mac"] = addr.get("addr", "")
                host_data["vendor"] = addr.get("vendor", "")
        
        # Hostnames
        hostnames = []
        for hn in host.findall("hostnames/hostname"):
            hostnames.append(hn.get("name", ""))
        host_data["hostnames"] = hostnames
        
        # Ports
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            
            port_data = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": "open",
                "service": "",
                "product": "",
                "version": "",
                "extrainfo": "",
                "cpe": [],
                "scripts": {}
            }
            
            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["product"] = service.get("product", "")
                port_data["version"] = service.get("version", "")
                port_data["extrainfo"] = service.get("extrainfo", "")
                
                for cpe in service.findall("cpe"):
                    if cpe.text:
                        port_data["cpe"].append(cpe.text)
            
            # Scripts
            for script in port.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                port_data["scripts"][script_id] = script_output
            
            host_data["ports"].append(port_data)
        
        results["hosts"].append(host_data)
    
    return results


def search_nvd_cves(product: str, version: str = "") -> list:
    """Search NVD (National Vulnerability Database) for CVEs"""
    if not product:
        return []
    
    try:
        # Build search keyword
        keyword = product
        if version:
            keyword = f"{product} {version}"
        
        keyword = keyword.strip()
        if not keyword:
            return []
        
        encoded = urllib.parse.quote(keyword)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=5"
        
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "VulnScanner/1.0")
        
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Get description
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )
            
            # Get CVSS score
            metrics = cve.get("metrics", {})
            score = None
            severity = "UNKNOWN"
            
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = metric_list[0].get("baseSeverity", 
                                cvss_data.get("baseSeverity", "UNKNOWN"))
                    break
            
            # Get references
            references = [r.get("url", "") for r in cve.get("references", [])[:3]]
            
            cves.append({
                "id": cve_id,
                "description": description[:300] + "..." if len(description) > 300 else description,
                "score": score,
                "severity": severity,
                "references": references,
                "published": cve.get("published", "")[:10]
            })
        
        return cves
        
    except Exception as e:
        print(f"[!] CVE lookup failed for '{product}': {e}", file=sys.stderr)
        return []


def get_mitigation_advice(service: str, product: str, cves: list) -> list:
    """Generate mitigation advice based on service and CVEs"""
    advice = []
    
    service_lower = (service or "").lower()
    product_lower = (product or "").lower()
    
    # Service-specific advice
    service_advice = {
        "ssh": [
            "Disable root login (PermitRootLogin no)",
            "Use SSH key authentication instead of passwords",
            "Change default port 22 to a non-standard port",
            "Implement fail2ban to prevent brute-force attacks",
            "Restrict SSH access to specific IP ranges using AllowUsers/DenyUsers"
        ],
        "http": [
            "Enable HTTPS and redirect all HTTP traffic to HTTPS",
            "Implement Content Security Policy (CSP) headers",
            "Add X-Frame-Options, X-Content-Type-Options headers",
            "Keep web server software updated to latest stable version",
            "Disable directory listing and server version disclosure"
        ],
        "https": [
            "Ensure TLS 1.2+ is used (disable TLS 1.0 and 1.1)",
            "Use strong cipher suites (ECDHE, AES-GCM)",
            "Implement HSTS (HTTP Strict Transport Security)",
            "Regularly renew SSL/TLS certificates",
            "Enable OCSP stapling for certificate validation"
        ],
        "ftp": [
            "Replace FTP with SFTP or FTPS (encrypted alternatives)",
            "Disable anonymous FTP access",
            "Restrict FTP access to specific IP addresses",
            "Use chroot jail to isolate FTP users",
            "Regularly audit FTP access logs"
        ],
        "smtp": [
            "Enable SMTP authentication to prevent open relay",
            "Implement SPF, DKIM, and DMARC records",
            "Use TLS for SMTP connections",
            "Rate-limit connections to prevent spam abuse",
            "Regularly update mail server software"
        ],
        "mysql": [
            "Never expose MySQL directly to the internet",
            "Use strong passwords and the principle of least privilege",
            "Bind MySQL to localhost (127.0.0.1) only",
            "Disable the 'test' database and anonymous accounts",
            "Enable MySQL audit logging"
        ],
        "postgresql": [
            "Restrict connections via pg_hba.conf",
            "Use SSL for all remote connections",
            "Apply principle of least privilege for database users",
            "Regularly update PostgreSQL to latest stable version",
            "Enable logging of all connections and queries"
        ],
        "rdp": [
            "Enable Network Level Authentication (NLA)",
            "Use a VPN instead of exposing RDP directly",
            "Implement account lockout policies",
            "Change default RDP port 3389",
            "Use multi-factor authentication for RDP access"
        ],
        "smb": [
            "Disable SMBv1 immediately (vulnerable to EternalBlue)",
            "Restrict SMB access to necessary hosts only",
            "Enable SMB signing to prevent MITM attacks",
            "Keep Windows systems patched and updated",
            "Block SMB ports (445, 139) at the firewall"
        ],
        "dns": [
            "Disable recursive DNS queries from external hosts",
            "Implement DNSSEC for zone integrity",
            "Rate-limit DNS responses to prevent amplification attacks",
            "Regularly audit DNS zone transfers",
            "Keep DNS software updated"
        ],
        "telnet": [
            "IMMEDIATELY disable Telnet - it transmits data in plaintext",
            "Replace with SSH for all remote administration",
            "Block Telnet port (23) at firewall level",
            "Audit all systems for Telnet service and disable it"
        ]
    }
    
    # Match service
    for svc, tips in service_advice.items():
        if svc in service_lower or svc in product_lower:
            advice.extend(tips)
            break
    
    # Generic advice if no specific match
    if not advice:
        advice = [
            f"Keep {product or service} updated to the latest stable version",
            "Apply principle of least privilege for service access",
            "Monitor service logs for suspicious activity",
            "Implement firewall rules to restrict access to authorized hosts only",
            "Consider whether this service needs to be publicly accessible"
        ]
    
    # Add CVE-specific advice
    if cves:
        critical_cves = [c for c in cves if c.get("severity") in ["CRITICAL", "HIGH"]]
        if critical_cves:
            advice.insert(0, f"⚠️ URGENT: {len(critical_cves)} critical/high CVEs found - patch immediately")
            advice.insert(1, "Check vendor security advisories for available patches")
    
    # General security advice
    advice.append("Implement intrusion detection/prevention system (IDS/IPS)")
    advice.append("Regular vulnerability scanning and penetration testing")
    
    return advice[:8]  # Return top 8 recommendations


def scan_and_analyze(target: str) -> dict:
    """Main function: scan target and analyze vulnerabilities"""
    print(f"[*] Starting vulnerability assessment for: {target}", file=sys.stderr)
    
    # Run port scan
    scan_results = run_nmap_scan(target)
    
    if "error" in scan_results:
        return scan_results
    
    # For each open port, look up CVEs
    for host in scan_results.get("hosts", []):
        for port in host.get("ports", []):
            service = port.get("service", "")
            product = port.get("product", "")
            version = port.get("version", "")
            
            print(f"[*] Looking up CVEs for: {product or service} {version}", file=sys.stderr)
            
            # Search NVD
            cves = []
            if product:
                cves = search_nvd_cves(product, version)
                time.sleep(0.5)  # Rate limit NVD API
            
            if not cves and service:
                cves = search_nvd_cves(service, version)
                time.sleep(0.5)
            
            port["cves"] = cves
            port["mitigations"] = get_mitigation_advice(service, product, cves)
            
            # Calculate risk score
            if cves:
                max_score = max((c.get("score") or 0) for c in cves)
                port["risk_score"] = max_score
                if max_score >= 9.0:
                    port["risk_level"] = "CRITICAL"
                elif max_score >= 7.0:
                    port["risk_level"] = "HIGH"
                elif max_score >= 4.0:
                    port["risk_level"] = "MEDIUM"
                else:
                    port["risk_level"] = "LOW"
            else:
                port["risk_score"] = None
                port["risk_level"] = "UNKNOWN"
    
    return scan_results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 backend.py <target>"}))
        sys.exit(1)
    
    target = sys.argv[1]
    results = scan_and_analyze(target)
    print(json.dumps(results, indent=2))

    if "--discover" in sys.argv:
    idx=sys.argv.index("--discover")
    print(json.dumps(network_discovery(sys.argv[idx+1]),indent=2))
else:
    mods=["ports","ssl","dns","headers"]
    if "--modules" in sys.argv:
        idx=sys.argv.index("--modules")
        mods=sys.argv[idx+1].split(",")
        target=sys.argv[-1]
    else:
        target=sys.argv[1]
    print(json.dumps(full_scan(target,mods),indent=2))
