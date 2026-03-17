#!/usr/bin/env python3
import json, sys, subprocess, urllib.request, urllib.parse, time, re, socket, ssl
import xml.etree.ElementTree as ET
from datetime import datetime

# ─── TOR / PROXY CONFIGURATION ───────────────
# All external connections are routed through Tor (SOCKS5 on 127.0.0.1:9050)
# nmap uses proxychains; Python HTTP uses urllib via SOCKS5 proxy handler

TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050

def get_tor_opener():
    """
    Returns a urllib opener that routes through Tor SOCKS5.
    Requires: pip3 install PySocks --break-system-packages
    Falls back to direct if PySocks not available.
    """
    try:
        import socks
        import socket as _socket
        # Monkey-patch socket for this process
        socks.set_default_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
        _socket.socket = socks.socksocket
        return urllib.request.build_opener()
    except ImportError:
        print("[!] PySocks not installed — HTTP requests won't use Tor.", file=sys.stderr)
        print("[!] Fix: pip3 install PySocks --break-system-packages", file=sys.stderr)
        return urllib.request.build_opener()

# Build the Tor opener once at module load
_tor_opener = None
def tor_opener():
    global _tor_opener
    if _tor_opener is None:
        _tor_opener = get_tor_opener()
    return _tor_opener

def tor_urlopen(url, headers=None, timeout=30, data=None):
    """
    Open a URL through Tor. Wraps urllib with SOCKS5 proxy and custom headers.
    """
    req = urllib.request.Request(url, data=data)
    req.add_header("User-Agent", "Mozilla/5.0 VulnScanner/2.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        # Try to use socks-patched socket
        opener = tor_opener()
        return opener.open(req, timeout=timeout)
    except Exception:
        # Fallback to standard urlopen
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)


# ─── NMAP PORT SCAN (via proxychains) ─────────
# IMPORTANT NOTES FOR TOR/PROXYCHAINS SCANNING:
#   - Must use -sT (TCP connect) — SYN scans don't work through proxychains
#   - Must use -Pn (skip ping) — ICMP doesn't work through Tor
#   - Reduced port range (top 1000) for speed — full range would timeout
#   - Increased timeout values to handle Tor latency (~300–2000ms per hop)
#   - Removed version intensity to reduce connection count
#   - Results may be partial — Tor exit nodes sometimes block ports

def run_nmap_scan(target):
    """
    Runs nmap through proxychains (Tor).
    Uses TCP connect scan with conservative timing for proxy reliability.
    """
    try:
        cmd = [
            "proxychains4", "-q",   # -q = quiet mode, suppress proxychains output
            "nmap",
            "-sT",                   # TCP connect scan (REQUIRED for proxychains)
            "-Pn",                   # Skip host discovery (REQUIRED — ICMP blocked by Tor)
            "-n",                    # No DNS resolution (faster, avoids DNS leaks)
            "--open",                # Only show open ports
            "-T2",                   # Timing: polite — avoids timeouts through Tor
                                     # T1=sneaky, T2=polite, T3=normal(default), T4=aggressive
            "--host-timeout", "300s",# Abort host after 5 min (Tor is slow)
            "--max-retries", "1",    # Only retry once — retries waste time on proxies
            "--min-rtt-timeout", "500ms",
            "--max-rtt-timeout", "10000ms",  # Up to 10s per probe (Tor latency)
            "--initial-rtt-timeout", "2000ms",
            "-sV",                   # Version detection
            "--version-intensity", "2",  # Light version detection (fewer probes = faster)
            "--top-ports", "200",    # Scan top 200 ports instead of 1-10000
                                     # Full range through Tor would take 30+ minutes
            "-oX", "-",             # XML output to stdout
            target
        ]

        print(f"[*] Starting proxychains nmap scan on: {target}", file=sys.stderr)
        print(f"[*] Note: Tor routing active — scan may take 3–10 minutes", file=sys.stderr)

        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600   # 10 minute timeout for full Tor scan
        )

        if r.returncode != 0 and not r.stdout.strip():
            stderr = r.stderr.strip()[:500]
            # Check for common proxychains errors
            if "proxychains" in stderr.lower() or "can't assign" in stderr.lower():
                return {"error": f"proxychains error: {stderr}. Make sure proxychains4 is installed and Tor is running on port {TOR_SOCKS_PORT}."}
            return {"error": f"nmap error (exit {r.returncode}): {stderr}"}

        if not r.stdout.strip():
            return {"error": "nmap produced no output — target may be unreachable through Tor, or Tor is not running"}

        return parse_nmap_xml(r.stdout)

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 10 minutes. Through Tor this is normal for large ranges. Try a specific IP or reduce scope."}
    except FileNotFoundError as e:
        missing = "proxychains4" if "proxychains" in str(e) else "nmap"
        return {"error": f"{missing} not found. Install: sudo apt install {missing}"}
    except Exception as e:
        return {"error": str(e)}


def parse_nmap_xml(xml_output):
    if not xml_output or not xml_output.strip():
        return {"error": "Empty nmap output — target may be unreachable or blocked by Tor exit node"}
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"Failed to parse nmap output: {e}"}

    results = {"scan_info": {}, "hosts": []}
    rs = root.find("runstats/finished")
    if rs is not None:
        results["scan_info"]["elapsed"] = rs.get("elapsed", "")
        results["scan_info"]["summary"] = rs.get("summary", "")

    for host in root.findall("host"):
        hd = {
            "ports": [], "os": None, "status": "unknown",
            "ip": "", "mac": "", "vendor": "", "hostnames": []
        }
        st = host.find("status")
        if st is not None:
            hd["status"] = st.get("state", "unknown")
        for addr in host.findall("address"):
            at = addr.get("addrtype", "")
            if at == "ipv4":
                hd["ip"] = addr.get("addr", "")
            elif at == "mac":
                hd["mac"] = addr.get("addr", "")
                hd["vendor"] = addr.get("vendor", "")
        hd["hostnames"] = [h.get("name", "") for h in host.findall("hostnames/hostname")]
        for om in host.findall("os/osmatch"):
            hd["os"] = om.get("name", "")
            hd["os_accuracy"] = om.get("accuracy", "")
            break
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pd = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": "open", "service": "", "product": "",
                "version": "", "extrainfo": "", "cpe": [], "scripts": {}
            }
            svc = port.find("service")
            if svc is not None:
                pd["service"] = svc.get("name", "")
                pd["product"] = svc.get("product", "")
                pd["version"] = svc.get("version", "")
                pd["extrainfo"] = svc.get("extrainfo", "")
                pd["cpe"] = [c.text for c in svc.findall("cpe") if c.text]
            for scr in port.findall("script"):
                pd["scripts"][scr.get("id", "")] = scr.get("output", "")
            hd["ports"].append(pd)
        results["hosts"].append(hd)

    return results


# ─── NETWORK DISCOVERY (via proxychains) ──────
def network_discovery(subnet):
    """
    Discover live hosts on a subnet through Tor/proxychains.
    NOTE: Host discovery is very limited through Tor — only TCP-based
    discovery works. ICMP ping is blocked.
    """
    try:
        cmd = [
            "proxychains4", "-q",
            "nmap",
            "-sT",          # TCP connect (proxychains requirement)
            "-Pn",          # No ping (ICMP blocked by Tor)
            "-n",           # No DNS
            "--open",
            "-T2",          # Polite timing
            "--host-timeout", "120s",
            "--max-retries", "1",
            "--top-ports", "10",   # Just check top 10 ports to detect hosts
            "-oX", "-",
            subnet
        ]
        print(f"[*] Network discovery via proxychains: {subnet}", file=sys.stderr)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not r.stdout.strip():
            return {"error": f"No output from nmap: {r.stderr.strip()[:200]}"}

        root = ET.fromstring(r.stdout)
        hosts = []
        for host in root.findall("host"):
            st = host.find("status")
            if st is None or st.get("state") != "up":
                continue
            hd = {"status": "up", "ip": "", "mac": "", "vendor": "", "hostnames": []}
            for addr in host.findall("address"):
                at = addr.get("addrtype", "")
                if at == "ipv4":
                    hd["ip"] = addr.get("addr", "")
                elif at == "mac":
                    hd["mac"] = addr.get("addr", "")
                    hd["vendor"] = addr.get("vendor", "")
            hd["hostnames"] = [h.get("name", "") for h in host.findall("hostnames/hostname")]
            if hd["ip"]:
                hosts.append(hd)

        return {"hosts": hosts, "total": len(hosts)}

    except subprocess.TimeoutExpired:
        return {"error": "Network discovery timed out. Subnet scanning through Tor is very slow."}
    except FileNotFoundError:
        return {"error": "proxychains4 or nmap not found. Install: sudo apt install proxychains4 nmap"}
    except Exception as e:
        return {"error": str(e)}


# ─── CVE LOOKUP (via Tor) ─────────────────────
NVD_API_KEY = ""  # Optional: free key from https://nvd.nist.gov/developers/request-an-api-key

def search_nvd_cves(product, version="", retries=3):
    """
    Query NVD for CVEs. Routes through Tor for anonymity.
    Increased timeout and retry delays for Tor latency.
    """
    if not product:
        return []
    try:
        kw = f"{product} {version}".strip()
        url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?keywordSearch={urllib.parse.quote(kw)}&resultsPerPage=5")
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        for attempt in range(retries):
            try:
                with tor_urlopen(url, headers=headers, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    # Rate limit — Tor exit nodes share IP so rate limits hit faster
                    wait = 60 if not NVD_API_KEY else 10
                    print(f"[!] NVD rate limit — waiting {wait}s (attempt {attempt+1}/{retries})", file=sys.stderr)
                    time.sleep(wait)
                    continue
                return []
            except Exception as exc:
                print(f"[!] NVD attempt {attempt+1} failed: {exc}", file=sys.stderr)
                if attempt < retries - 1:
                    time.sleep(8)
                    continue
                return []

        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "No description")
            metrics = cve.get("metrics", {})
            score, severity = None, "UNKNOWN"
            for mk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                ml = metrics.get(mk, [])
                if ml:
                    cd = ml[0].get("cvssData", {})
                    score = cd.get("baseScore")
                    severity = ml[0].get("baseSeverity", cd.get("baseSeverity", "UNKNOWN"))
                    break
            has_exploit = any(
                "exploit" in r.get("url", "").lower() or "github" in r.get("url", "").lower()
                for r in cve.get("references", [])
            )
            cves.append({
                "id": cve.get("id", ""),
                "description": desc[:350] + "..." if len(desc) > 350 else desc,
                "score": score,
                "severity": severity,
                "has_exploit": has_exploit,
                "references": [r.get("url", "") for r in cve.get("references", [])[:3]],
                "published": cve.get("published", "")[:10]
            })
        return cves

    except Exception as e:
        print(f"[!] CVE lookup failed for {product}: {e}", file=sys.stderr)
        return []


# ─── SSL ANALYSIS (via Tor/SOCKS5) ────────────
def analyze_ssl(host, port=443):
    """
    Analyze SSL/TLS through Tor SOCKS5 proxy.
    Uses PySocks to connect through Tor before doing TLS handshake.
    """
    result = {"host": host, "port": port, "grade": "F", "issues": [], "details": {}}
    try:
        # Try SOCKS5 connection through Tor first
        try:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, TOR_SOCKS_HOST, TOR_SOCKS_PORT)
            sock.settimeout(30)
            sock.connect((host, port))
        except ImportError:
            # Fallback to direct connection
            sock = socket.create_connection((host, port), timeout=30)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

            result["details"]["protocol"] = version
            result["details"]["cipher"] = cipher[0] if cipher else ""
            result["details"]["cipher_bits"] = cipher[2] if cipher else 0

            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["details"]["subject"] = subject.get("commonName", "")
                result["details"]["issuer"] = issuer.get("organizationName", "")
                exp = cert.get("notAfter", "")
                if exp:
                    try:
                        exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp_dt - datetime.utcnow()).days
                        result["details"]["expires"] = exp
                        result["details"]["days_until_expiry"] = days_left
                        if days_left < 0:
                            result["issues"].append({"severity": "CRITICAL", "msg": "Certificate EXPIRED"})
                        elif days_left < 30:
                            result["issues"].append({"severity": "HIGH", "msg": f"Expires in {days_left} days"})
                        elif days_left < 90:
                            result["issues"].append({"severity": "MEDIUM", "msg": f"Expires in {days_left} days"})
                    except Exception:
                        pass

            if version in ["TLSv1", "TLSv1.1", "SSLv2", "SSLv3"]:
                result["issues"].append({"severity": "HIGH", "msg": f"Weak protocol: {version}"})
            if cipher:
                cn = cipher[0].upper()
                if "RC4" in cn:
                    result["issues"].append({"severity": "CRITICAL", "msg": "RC4 cipher (broken)"})
                if "DES" in cn:
                    result["issues"].append({"severity": "CRITICAL", "msg": "DES cipher (broken)"})
                if "NULL" in cn:
                    result["issues"].append({"severity": "CRITICAL", "msg": "NULL cipher"})

            crit = sum(1 for i in result["issues"] if i["severity"] == "CRITICAL")
            high = sum(1 for i in result["issues"] if i["severity"] == "HIGH")
            if crit > 0:
                result["grade"] = "F"
            elif high > 0:
                result["grade"] = "C"
            elif len(result["issues"]) > 0:
                result["grade"] = "B"
            elif version == "TLSv1.3":
                result["grade"] = "A+"
            else:
                result["grade"] = "A"

    except ConnectionRefusedError:
        result["issues"].append({"severity": "INFO", "msg": f"Port {port} not open or SSL not available"})
        result["grade"] = "N/A"
    except socket.timeout:
        result["issues"].append({"severity": "INFO", "msg": f"SSL connection timed out on port {port} (Tor latency)"})
        result["grade"] = "N/A"
    except Exception as e:
        result["issues"].append({"severity": "INFO", "msg": f"SSL check: {str(e)}"})
        result["grade"] = "N/A"

    return result


# ─── DNS RECON ────────────────────────────────
def dns_recon(target):
    """
    DNS recon. dig queries go through system resolver (not Tor — DNS uses UDP).
    For anonymity, DNS queries are sent to a public resolver via proxychains if needed.
    """
    result = {
        "target": target, "records": {}, "issues": [],
        "subdomains": [], "has_spf": False, "has_dmarc": False
    }

    dig_available = False
    try:
        subprocess.run(["dig", "-v"], capture_output=True, timeout=3)
        dig_available = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # DNS queries — use dig with increased timeout for proxychains if desired
    # Note: dig uses UDP which doesn't work through SOCKS, so we use direct DNS
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            if dig_available:
                r = subprocess.run(
                    ["dig", "+short", "+time=10", "+tries=2", rtype, target],
                    capture_output=True, text=True, timeout=15
                )
                if r.stdout.strip():
                    result["records"][rtype] = [
                        l.strip() for l in r.stdout.strip().split("\n") if l.strip()
                    ]
            else:
                r = subprocess.run(
                    ["nslookup", "-type=" + rtype, target],
                    capture_output=True, text=True, timeout=15
                )
                lines = [l.strip() for l in r.stdout.split("\n") if l.strip() and "=" in l]
                if lines:
                    result["records"][rtype] = lines
        except Exception:
            pass

    if "A" not in result["records"]:
        try:
            ip = socket.gethostbyname(target)
            result["records"]["A"] = [ip]
        except Exception:
            pass

    txt = result["records"].get("TXT", [])
    result["has_spf"] = any("v=spf1" in t for t in txt)
    result["has_dmarc"] = any("v=DMARC1" in t for t in txt)
    if not result["has_spf"]:
        result["issues"].append({"severity": "HIGH", "msg": "No SPF record — email spoofing risk"})
    if not result["has_dmarc"]:
        result["issues"].append({"severity": "MEDIUM", "msg": "No DMARC record — email spoofing risk"})

    if dig_available:
        for ns in result["records"].get("NS", [])[:2]:
            try:
                r = subprocess.run(
                    ["dig", "axfr", target, f"@{ns.rstrip('.')}"],
                    capture_output=True, text=True, timeout=20
                )
                if "Transfer failed" not in r.stdout and len(r.stdout) > 200:
                    result["issues"].append({"severity": "CRITICAL", "msg": f"Zone transfer ALLOWED from {ns}"})
            except Exception:
                pass

    for sub in ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "vpn",
                "smtp", "pop", "imap", "remote", "portal", "shop", "blog", "app",
                "cdn", "ns1", "ns2"]:
        try:
            fqdn = f"{sub}.{target}"
            socket.setdefaulttimeout(5)
            ip = socket.gethostbyname(fqdn)
            result["subdomains"].append({"subdomain": fqdn, "ip": ip})
        except Exception:
            pass

    if not dig_available:
        result["issues"].append({
            "severity": "INFO",
            "msg": "dig not found — install dnsutils: sudo apt-get install dnsutils"
        })

    return result


# ─── SUBDOMAIN FINDER ─────────────────────────
def subdomain_finder(domain, wordlist_size="medium"):
    """
    Subdomain enumeration. DNS brute-force uses direct DNS (UDP, not proxied).
    crt.sh and HackerTarget queries go through Tor.
    """
    result = {"domain": domain, "subdomains": [], "total": 0, "sources": []}
    found = {}

    small = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "vpn", "smtp",
             "pop3", "imap", "remote", "portal", "shop", "blog", "app", "cdn", "ns1", "ns2",
             "mx", "webmail", "cpanel", "whm", "autodiscover", "autoconfig", "mobile", "m",
             "static", "media", "img", "assets", "login", "secure", "beta", "alpha", "demo",
             "docs", "help", "support", "status", "monitor"]
    medium = small + ["git", "gitlab", "github", "jenkins", "jira", "confluence", "wiki", "kb",
                      "forum", "community", "chat", "slack", "teams", "meet", "video", "stream",
                      "api2", "v2", "v1", "old", "new", "backup", "bak", "temp", "tmp", "db",
                      "database", "mysql", "redis", "elastic", "search", "kibana", "grafana",
                      "prometheus", "vault", "consul", "etcd", "prod", "production", "stage",
                      "uat", "qa", "testing", "sandbox", "preview", "internal", "intranet",
                      "extranet", "private", "public", "external", "dmz"]
    wordlist = medium if wordlist_size == "medium" else small

    result["sources"].append("dns_bruteforce")
    for sub in wordlist:
        try:
            fqdn = f"{sub}.{domain}"
            socket.setdefaulttimeout(5)
            ips = socket.getaddrinfo(fqdn, None)
            ip = ips[0][4][0] if ips else ""
            if ip and fqdn not in found:
                found[fqdn] = {"subdomain": fqdn, "ip": ip, "source": "dns_bruteforce", "cname": ""}
        except Exception:
            pass

    # crt.sh — through Tor
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with tor_urlopen(url, timeout=45) as resp:
            certs = json.loads(resp.read().decode())
        result["sources"].append("crt.sh")
        for cert in certs[:200]:
            names = cert.get("name_value", "").split("\n")
            for name in names:
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    if name not in found:
                        try:
                            socket.setdefaulttimeout(5)
                            ip = socket.gethostbyname(name)
                            found[name] = {"subdomain": name, "ip": ip, "source": "crt.sh", "cname": ""}
                        except Exception:
                            found[name] = {"subdomain": name, "ip": "(not resolved)", "source": "crt.sh", "cname": ""}
    except Exception as e:
        print(f"[!] crt.sh lookup failed: {e}", file=sys.stderr)

    # HackerTarget — through Tor
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        with tor_urlopen(url, timeout=30) as resp:
            lines = resp.read().decode().strip().split("\n")
        result["sources"].append("hackertarget")
        for line in lines:
            if "," in line:
                parts = line.split(",")
                sub = parts[0].strip()
                ip = parts[1].strip() if len(parts) > 1 else ""
                if sub.endswith(f".{domain}") and sub not in found:
                    found[sub] = {"subdomain": sub, "ip": ip, "source": "hackertarget", "cname": ""}
    except Exception as e:
        print(f"[!] HackerTarget lookup failed: {e}", file=sys.stderr)

    result["subdomains"] = sorted(found.values(), key=lambda x: x["subdomain"])
    result["total"] = len(result["subdomains"])
    return result


# ─── DIRECTORY ENUMERATOR (via Tor) ───────────
def dir_enum(target_url, wordlist_size="small", extensions="php,html,txt,bak,zip"):
    """
    Directory busting through Tor SOCKS5.
    Reduced concurrency and longer timeouts due to Tor latency.
    """
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")

    result = {"url": target_url, "found": [], "total": 0, "scanned": 0, "errors": 0}

    small_paths = [
        "admin", "login", "wp-admin", "administrator", "phpmyadmin", "dashboard", "panel",
        "cpanel", "webmail", "manager", "management", "console", "control", "portal",
        "api", "api/v1", "api/v2", "swagger", "docs", "documentation", "readme",
        "backup", "bak", "old", "temp", "tmp", ".git", "config", "configuration",
        "robots.txt", "sitemap.xml", ".env", "web.config", "phpinfo.php",
        "install", "setup", "update", "upgrade", "test", "debug", "info",
        "uploads", "upload", "files", "images", "static", "assets", "media",
        "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
        "server-status", "server-info", ".htaccess", ".htpasswd",
        "user", "users", "account", "accounts", "profile", "register", "signup",
        "logout", "signout", "passwd", "password", "credentials",
        "shell", "cmd", "command", "exec", "execute", "run", "eval",
        "db", "database", "sql", "mysql", "sqlite", "mongo", "redis",
        "log", "logs", "error", "errors", "access", "audit", "trace",
        "404", "500", "error_log", "access_log", "debug.log", "app.log"
    ]
    medium_paths = small_paths + [
        "jenkins", "gitlab", "github", "jira", "confluence", "wiki",
        "grafana", "kibana", "elastic", "prometheus", "vault", "consul",
        "phpMyAdmin", "PMA", "pma", "myadmin", "dbadmin", "sqladmin",
        "wp-json", "wp-cron.php", "license.txt", "changelog.txt",
        "composer.json", "package.json", ".gitignore", ".DS_Store",
        "Thumbs.db", "desktop.ini", "web.config.bak", "web.config.old",
        "application", "app", "apps", "service", "services", "rest", "soap",
        "v1", "v2", "v3", "health", "status", "ping", "metrics", "monitor",
        "secret", "secrets", "private", "hidden", "internal", "dev", "staging",
        "cgi-bin", "scripts", "bin", "lib", "include", "includes", "src",
        "classes", "models", "views", "controllers", "helpers", "utils",
        "index.php", "index.html", "index.asp", "index.aspx", "default.asp",
        "home", "main", "welcome", "start", "begin", "init", "bootstrap"
    ]
    paths = medium_paths if wordlist_size == "medium" else small_paths
    exts = [""] + [f".{e.strip()}" for e in extensions.split(",") i
