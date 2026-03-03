#!/usr/bin/env python3
import json,sys,subprocess,urllib.request,urllib.parse,time,re,socket,ssl
import xml.etree.ElementTree as ET
from datetime import datetime

# ─── NMAP PORT SCAN ───────────────────────────
def run_nmap_scan(target):
    try:
        cmd=["nmap","-sV","--version-intensity","5","-sC","-T4","--open",
             "-p","1-10000","--script","banner,http-title,ssl-cert","-oX","-",target]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        return parse_nmap_xml(r.stdout)
    except subprocess.TimeoutExpired: return {"error":"Scan timed out"}
    except FileNotFoundError: return {"error":"nmap not found: sudo apt-get install nmap"}
    except Exception as e: return {"error":str(e)}

def parse_nmap_xml(xml_output):
    try: root=ET.fromstring(xml_output)
    except ET.ParseError: return {"error":"Failed to parse nmap output"}
    results={"scan_info":{},"hosts":[]}
    rs=root.find("runstats/finished")
    if rs is not None:
        results["scan_info"]["elapsed"]=rs.get("elapsed","")
        results["scan_info"]["summary"]=rs.get("summary","")
    for host in root.findall("host"):
        hd={"ports":[],"os":None,"status":"unknown","ip":"","mac":"","vendor":"","hostnames":[]}
        st=host.find("status")
        if st is not None: hd["status"]=st.get("state","unknown")
        for addr in host.findall("address"):
            at=addr.get("addrtype","")
            if at=="ipv4": hd["ip"]=addr.get("addr","")
            elif at=="mac": hd["mac"]=addr.get("addr",""); hd["vendor"]=addr.get("vendor","")
        hd["hostnames"]=[h.get("name","") for h in host.findall("hostnames/hostname")]
        for om in host.findall("os/osmatch"):
            hd["os"]=om.get("name",""); hd["os_accuracy"]=om.get("accuracy",""); break
        for port in host.findall("ports/port"):
            state=port.find("state")
            if state is None or state.get("state")!="open": continue
            pd={"port":int(port.get("portid",0)),"protocol":port.get("protocol","tcp"),
                "state":"open","service":"","product":"","version":"","extrainfo":"","cpe":[],"scripts":{}}
            svc=port.find("service")
            if svc is not None:
                pd["service"]=svc.get("name",""); pd["product"]=svc.get("product","")
                pd["version"]=svc.get("version",""); pd["extrainfo"]=svc.get("extrainfo","")
                pd["cpe"]=[c.text for c in svc.findall("cpe") if c.text]
            for scr in port.findall("script"):
                pd["scripts"][scr.get("id","")]=scr.get("output","")
            hd["ports"].append(pd)
        results["hosts"].append(hd)
    return results

# ─── NETWORK DISCOVERY ────────────────────────
def network_discovery(subnet):
    try:
        cmd=["nmap","-sn","-T4","--open","-oX","-",subnet]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        root=ET.fromstring(r.stdout)
        hosts=[]
        for host in root.findall("host"):
            st=host.find("status")
            if st is None or st.get("state")!="up": continue
            hd={"status":"up","ip":"","mac":"","vendor":"","hostnames":[]}
            for addr in host.findall("address"):
                at=addr.get("addrtype","")
                if at=="ipv4": hd["ip"]=addr.get("addr","")
                elif at=="mac": hd["mac"]=addr.get("addr",""); hd["vendor"]=addr.get("vendor","")
            hd["hostnames"]=[h.get("name","") for h in host.findall("hostnames/hostname")]
            if hd["ip"]: hosts.append(hd)
        return {"hosts":hosts,"total":len(hosts)}
    except Exception as e: return {"error":str(e)}

# ─── CVE LOOKUP ───────────────────────────────
def search_nvd_cves(product,version=""):
    if not product: return []
    try:
        kw=f"{product} {version}".strip()
        url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(kw)}&resultsPerPage=5"
        req=urllib.request.Request(url,headers={"User-Agent":"VulnScanner/2.0"})
        with urllib.request.urlopen(req,timeout=10) as resp:
            data=json.loads(resp.read().decode())
        cves=[]
        for vuln in data.get("vulnerabilities",[]):
            cve=vuln.get("cve",{})
            descs=cve.get("descriptions",[])
            desc=next((d["value"] for d in descs if d.get("lang")=="en"),"No description")
            metrics=cve.get("metrics",{})
            score,severity=None,"UNKNOWN"
            for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                ml=metrics.get(mk,[])
                if ml:
                    cd=ml[0].get("cvssData",{})
                    score=cd.get("baseScore")
                    severity=ml[0].get("baseSeverity",cd.get("baseSeverity","UNKNOWN"))
                    break
            has_exploit=any("exploit" in r.get("url","").lower() or "github" in r.get("url","").lower()
                           for r in cve.get("references",[]))
            cves.append({"id":cve.get("id",""),"description":desc[:350]+"..." if len(desc)>350 else desc,
                        "score":score,"severity":severity,"has_exploit":has_exploit,
                        "references":[r.get("url","") for r in cve.get("references",[])[:3]],
                        "published":cve.get("published","")[:10]})
        return cves
    except Exception as e: return []

# ─── SSL ANALYSIS ─────────────────────────────
def analyze_ssl(host,port=443):
    result={"host":host,"port":port,"grade":"F","issues":[],"details":{}}
    try:
        ctx=ssl.create_default_context()
        ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        with socket.create_connection((host,port),timeout=10) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ssock:
                cert=ssock.getpeercert(); cipher=ssock.cipher(); version=ssock.version()
                result["details"]["protocol"]=version
                result["details"]["cipher"]=cipher[0] if cipher else ""
                result["details"]["cipher_bits"]=cipher[2] if cipher else 0
                if cert:
                    subject=dict(x[0] for x in cert.get("subject",[]))
                    issuer=dict(x[0] for x in cert.get("issuer",[]))
                    result["details"]["subject"]=subject.get("commonName","")
                    result["details"]["issuer"]=issuer.get("organizationName","")
                    exp=cert.get("notAfter","")
                    if exp:
                        try:
                            exp_dt=datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z")
                            days_left=(exp_dt-datetime.utcnow()).days
                            result["details"]["expires"]=exp
                            result["details"]["days_until_expiry"]=days_left
                            if days_left<0: result["issues"].append({"severity":"CRITICAL","msg":"Certificate EXPIRED"})
                            elif days_left<30: result["issues"].append({"severity":"HIGH","msg":f"Expires in {days_left} days"})
                            elif days_left<90: result["issues"].append({"severity":"MEDIUM","msg":f"Expires in {days_left} days"})
                        except: pass
                if version in ["TLSv1","TLSv1.1","SSLv2","SSLv3"]:
                    result["issues"].append({"severity":"HIGH","msg":f"Weak protocol: {version}"})
                if cipher:
                    cn=cipher[0].upper()
                    if "RC4" in cn: result["issues"].append({"severity":"CRITICAL","msg":"RC4 cipher (broken)"})
                    if "DES" in cn: result["issues"].append({"severity":"CRITICAL","msg":"DES cipher (broken)"})
                    if "NULL" in cn: result["issues"].append({"severity":"CRITICAL","msg":"NULL cipher"})
                crit=sum(1 for i in result["issues"] if i["severity"]=="CRITICAL")
                high=sum(1 for i in result["issues"] if i["severity"]=="HIGH")
                if crit>0: result["grade"]="F"
                elif high>0: result["grade"]="C"
                elif len(result["issues"])>0: result["grade"]="B"
                elif version=="TLSv1.3": result["grade"]="A+"
                else: result["grade"]="A"
    except Exception as e:
        result["issues"].append({"severity":"INFO","msg":f"SSL check: {str(e)}"})
    return result

# ─── DNS RECON ────────────────────────────────
def dns_recon(target):
    result={"target":target,"records":{},"issues":[],"subdomains":[],"has_spf":False,"has_dmarc":False}
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            r=subprocess.run(["dig","+short",rtype,target],capture_output=True,text=True,timeout=10)
            if r.stdout.strip():
                result["records"][rtype]=[l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
        except: pass
    txt=result["records"].get("TXT",[])
    result["has_spf"]=any("v=spf1" in t for t in txt)
    result["has_dmarc"]=any("v=DMARC1" in t for t in txt)
    if not result["has_spf"]: result["issues"].append({"severity":"HIGH","msg":"No SPF record"})
    if not result["has_dmarc"]: result["issues"].append({"severity":"MEDIUM","msg":"No DMARC record"})
    for ns in result["records"].get("NS",[])[:2]:
        try:
            r=subprocess.run(["dig","axfr",target,f"@{ns.rstrip('.')}"],capture_output=True,text=True,timeout=10)
            if "Transfer failed" not in r.stdout and len(r.stdout)>200:
                result["issues"].append({"severity":"CRITICAL","msg":f"Zone transfer ALLOWED from {ns}"})
        except: pass
    for sub in ["www","mail","ftp","admin","api","dev","staging","test","vpn","smtp","pop","imap","remote","portal","shop","blog","app","cdn","ns1","ns2"]:
        try:
            fqdn=f"{sub}.{target}"
            socket.setdefaulttimeout(2)
            ip=socket.gethostbyname(fqdn)
            result["subdomains"].append({"subdomain":fqdn,"ip":ip})
        except: pass
    return result

# ─── SUBDOMAIN FINDER ─────────────────────────
def subdomain_finder(domain,wordlist_size="medium"):
    result={"domain":domain,"subdomains":[],"total":0,"sources":[]}
    found={}

    # Source 1: DNS brute force
    small=["www","mail","ftp","admin","api","dev","staging","test","vpn","smtp","pop3","imap",
           "remote","portal","shop","blog","app","cdn","ns1","ns2","mx","webmail","cpanel",
           "whm","autodiscover","autoconfig","mobile","m","static","media","img","assets",
           "login","secure","beta","alpha","demo","docs","help","support","status","monitor"]
    medium=small+["git","gitlab","github","jenkins","jira","confluence","wiki","kb","forum",
                  "community","chat","slack","teams","meet","video","stream","api2","v2","v1",
                  "old","new","backup","bak","temp","tmp","db","database","mysql","redis",
                  "elastic","search","kibana","grafana","prometheus","vault","consul","etcd",
                  "prod","production","stage","uat","qa","testing","sandbox","preview",
                  "internal","intranet","extranet","private","public","external","dmz"]
    wordlist=medium if wordlist_size=="medium" else small

    for sub in wordlist:
        try:
            fqdn=f"{sub}.{domain}"
            socket.setdefaulttimeout(2)
            ips=socket.getaddrinfo(fqdn,None)
            ip=ips[0][4][0] if ips else ""
            if ip and fqdn not in found:
                found[fqdn]={"subdomain":fqdn,"ip":ip,"source":"dns_bruteforce","cname":""}
        except: pass

    # Source 2: Certificate Transparency (crt.sh)
    try:
        url=f"https://crt.sh/?q=%.{domain}&output=json"
        req=urllib.request.Request(url,headers={"User-Agent":"VulnScanner/2.0"})
        with urllib.request.urlopen(req,timeout=15) as resp:
            certs=json.loads(resp.read().decode())
        result["sources"].append("crt.sh")
        for cert in certs[:200]:
            names=cert.get("name_value","").split("\n")
            for name in names:
                name=name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name==domain:
                    if name not in found:
                        try:
                            socket.setdefaulttimeout(2)
                            ip=socket.gethostbyname(name)
                            found[name]={"subdomain":name,"ip":ip,"source":"crt.sh","cname":""}
                        except:
                            found[name]={"subdomain":name,"ip":"(not resolved)","source":"crt.sh","cname":""}
    except: pass

    # Source 3: HackerTarget
    try:
        url=f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req=urllib.request.Request(url,headers={"User-Agent":"VulnScanner/2.0"})
        with urllib.request.urlopen(req,timeout=10) as resp:
            lines=resp.read().decode().strip().split("\n")
        result["sources"].append("hackertarget")
        for line in lines:
            if "," in line:
                parts=line.split(",")
                sub=parts[0].strip(); ip=parts[1].strip() if len(parts)>1 else ""
                if sub.endswith(f".{domain}") and sub not in found:
                    found[sub]={"subdomain":sub,"ip":ip,"source":"hackertarget","cname":""}
    except: pass

    result["subdomains"]=sorted(found.values(),key=lambda x:x["subdomain"])
    result["total"]=len(result["subdomains"])
    result["sources"].append("dns_bruteforce")
    return result

# ─── DIRECTORY ENUMERATOR ─────────────────────
def dir_enum(target_url,wordlist_size="small",extensions="php,html,txt,bak,zip"):
    if not target_url.startswith("http"):
        target_url="http://"+target_url
    target_url=target_url.rstrip("/")

    result={"url":target_url,"found":[],"total":0,"scanned":0,"errors":0}

    small_paths=["admin","login","wp-admin","administrator","phpmyadmin","dashboard","panel",
                 "cpanel","webmail","manager","management","console","control","portal",
                 "api","api/v1","api/v2","swagger","docs","documentation","readme",
                 "backup","bak","old","temp","tmp",".git","config","configuration",
                 "robots.txt","sitemap.xml",".env","web.config","phpinfo.php",
                 "install","setup","update","upgrade","test","debug","info",
                 "uploads","upload","files","images","static","assets","media",
                 "wp-content","wp-includes","wp-login.php","xmlrpc.php",
                 "server-status","server-info",".htaccess",".htpasswd",
                 "user","users","account","accounts","profile","register","signup",
                 "logout","signout","passwd","password","credentials",
                 "shell","cmd","command","exec","execute","run","eval",
                 "db","database","sql","mysql","sqlite","mongo","redis",
                 "log","logs","error","errors","access","audit","trace",
                 "404","500","error_log","access_log","debug.log","app.log"]

    medium_paths=small_paths+["jenkins","gitlab","github","jira","confluence","wiki",
                 "grafana","kibana","elastic","prometheus","vault","consul",
                 "phpMyAdmin","PMA","pma","myadmin","dbadmin","sqladmin",
                 "wp-json","wp-cron.php","license.txt","changelog.txt",
                 "composer.json","package.json",".gitignore",".DS_Store",
                 "Thumbs.db","desktop.ini","web.config.bak","web.config.old",
                 "application","app","apps","service","services","rest","soap",
                 "v1","v2","v3","health","status","ping","metrics","monitor",
                 "secret","secrets","private","hidden","internal","dev","staging",
                 "cgi-bin","scripts","bin","lib","include","includes","src",
                 "classes","models","views","controllers","helpers","utils",
                 "index.php","index.html","index.asp","index.aspx","default.asp",
                 "home","main","welcome","start","begin","init","bootstrap"]

    paths=medium_paths if wordlist_size=="medium" else small_paths
    exts=[""] + [f".{e.strip()}" for e in extensions.split(",") if e.strip()]

    all_paths=[]
    for path in paths:
        if "." in path.split("/")[-1]:
            all_paths.append(path)
        else:
            for ext in exts:
                all_paths.append(path+ext)

    ctx=ssl.create_default_context()
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

    for path in all_paths[:500]:
        url=f"{target_url}/{path}"
        try:
            req=urllib.request.Request(url,headers={
                "User-Agent":"Mozilla/5.0 (compatible; VulnScanner/2.0)",
                "Accept":"*/*"})
            with urllib.request.urlopen(req,timeout=5,context=ctx) as resp:
                status=resp.status
                length=resp.headers.get("Content-Length","?")
                content_type=resp.headers.get("Content-Type","").split(";")[0]
                if status in [200,201,204,301,302,307,308,401,403]:
                    severity="HIGH" if status==200 else ("MEDIUM" if status in [301,302,307,308] else "LOW")
                    if any(s in path for s in ["admin","shell","config","backup",".env","passwd","sql","git","debug","log"]):
                        severity="CRITICAL" if status==200 else "HIGH"
                    result["found"].append({
                        "url":url,"status":status,"size":length,
                        "type":content_type,"severity":severity,
                        "note":get_dir_note(path,status)})
            result["scanned"]+=1
        except urllib.error.HTTPError as e:
            if e.code in [401,403]:
                result["found"].append({"url":url,"status":e.code,"size":"?",
                    "type":"","severity":"MEDIUM","note":"Access restricted — resource exists"})
            result["scanned"]+=1
        except: result["errors"]+=1; result["scanned"]+=1

    result["total"]=len(result["found"])
    result["found"].sort(key=lambda x:{"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("severity","LOW"),3))
    return result

def get_dir_note(path,status):
    notes={
        ".git":"Git repository exposed — source code may be accessible",
        ".env":"Environment file exposed — credentials may be visible",
        "phpinfo":"PHP configuration exposed",
        "phpmyadmin":"phpMyAdmin exposed — database admin interface",
        "wp-admin":"WordPress admin panel",
        "backup":"Backup file/directory found",
        ".htpasswd":"Password file exposed",
        "config":"Configuration file found",
        "admin":"Admin panel found",
        "shell":"Potential shell/command execution endpoint",
        "passwd":"Password file found",
        "sql":"Database file/endpoint found",
        "debug":"Debug interface exposed",
        "log":"Log file accessible",
        "robots.txt":"Robots.txt — check for hidden paths",
        ".DS_Store":"macOS metadata file — directory structure exposed",
        "composer.json":"Dependency file exposed — reveals technology stack",
    }
    for k,v in notes.items():
        if k in path.lower(): return v
    if status==401: return "Authentication required"
    if status==403: return "Forbidden — resource exists but access denied"
    if status in [301,302]: return "Redirect found"
    return "Resource found"

# ─── LOGIN BRUTE FORCE ────────────────────────
def brute_force_http(url,usernames,passwords,user_field="username",pass_field="password"):
    result={"url":url,"attempts":0,"found":[],"status":"running"}
    ctx=ssl.create_default_context()
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

    for username in usernames[:10]:
        for password in passwords[:50]:
            try:
                data=urllib.parse.urlencode({user_field:username,pass_field:password}).encode()
                req=urllib.request.Request(url,data=data,headers={
                    "User-Agent":"Mozilla/5.0","Content-Type":"application/x-www-form-urlencoded"})
                with urllib.request.urlopen(req,timeout=5,context=ctx) as resp:
                    body=resp.read().decode(errors="ignore")
                    # Heuristic: successful login usually redirects or lacks error keywords
                    fail_keywords=["invalid","incorrect","wrong","failed","error","denied","bad credentials","unauthorized"]
                    success_keywords=["dashboard","welcome","logout","profile","account","success"]
                    body_lower=body.lower()
                    is_fail=any(k in body_lower for k in fail_keywords)
                    is_success=any(k in body_lower for k in success_keywords)
                    if is_success and not is_fail:
                        result["found"].append({"username":username,"password":password,"status":resp.status})
                result["attempts"]+=1
                time.sleep(0.2)
            except: result["attempts"]+=1
    result["status"]="complete"
    return result

def brute_force_ssh(host,port,usernames,passwords):
    result={"host":host,"port":port,"attempts":0,"found":[],"status":"running","note":""}
    try:
        import paramiko
        for username in usernames[:5]:
            for password in passwords[:20]:
                try:
                    client=paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(host,port=int(port),username=username,password=password,timeout=5,banner_timeout=5)
                    result["found"].append({"username":username,"password":password})
                    client.close()
                except paramiko.AuthenticationException: pass
                except Exception: break
                result["attempts"]+=1
                time.sleep(0.3)
        result["status"]="complete"
    except ImportError:
        result["status"]="error"
        result["note"]="paramiko not installed: pip3 install paramiko --user"
    return result

# ─── WEB HEADERS ──────────────────────────────
def analyze_web_headers(target):
    result={"url":"","status_code":None,"headers":{},"issues":[],"score":0,"grade":"F","server":"","technologies":[]}
    for scheme in ["https","http"]:
        url=f"{scheme}://{target}" if not target.startswith("http") else target
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 VulnScanner/2.0"})
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with urllib.request.urlopen(req,timeout=10,context=ctx) as resp:
                result["url"]=url; result["status_code"]=resp.status
                headers=dict(resp.headers); result["headers"]=headers
                server=headers.get("Server",""); result["server"]=server
                if server:
                    result["technologies"].append(server)
                    if re.search(r'\d+\.\d+',server):
                        result["issues"].append({"severity":"MEDIUM","msg":f"Server version disclosed: {server}"})
                xpb=headers.get("X-Powered-By","")
                if xpb:
                    result["technologies"].append(xpb)
                    result["issues"].append({"severity":"LOW","msg":f"X-Powered-By disclosed: {xpb}"})
                score=100
                checks=[("Strict-Transport-Security","HSTS not set","HIGH"),
                        ("Content-Security-Policy","No CSP — XSS risk","HIGH"),
                        ("X-Frame-Options","No X-Frame-Options — Clickjacking","MEDIUM"),
                        ("X-Content-Type-Options","No X-Content-Type-Options","MEDIUM"),
                        ("Referrer-Policy","No Referrer-Policy","LOW"),
                        ("Permissions-Policy","No Permissions-Policy","LOW")]
                hdr_lower={k.lower() for k in headers}
                for hdr,msg,sev in checks:
                    if hdr.lower() not in hdr_lower:
                        result["issues"].append({"severity":sev,"msg":msg})
                        score-={"HIGH":20,"MEDIUM":10,"LOW":5}[sev]
                result["score"]=max(0,score)
                if score>=90: result["grade"]="A+"
                elif score>=75: result["grade"]="A"
                elif score>=60: result["grade"]="B"
                elif score>=45: result["grade"]="C"
                elif score>=30: result["grade"]="D"
                else: result["grade"]="F"
                break
        except Exception as e:
            result["issues"].append({"severity":"INFO","msg":f"Could not fetch {url}: {str(e)}"})
    return result

# ─── MITIGATIONS & RISK ───────────────────────
def get_mitigation_advice(service,product,cves):
    advice=[]; sl=(service or "").lower(); pl=(product or "").lower()
    svc_advice={
        "ssh":["Disable root login (PermitRootLogin no)","Use SSH key authentication","Change default port 22","Deploy fail2ban","Restrict to specific IPs"],
        "http":["Enable HTTPS, redirect all HTTP","Implement CSP headers","Add X-Frame-Options","Keep web server updated","Disable directory listing"],
        "https":["Ensure TLS 1.2+ only","Use ECDHE/AES-GCM ciphers","Enable HSTS","Renew certs before expiry"],
        "ftp":["Replace FTP with SFTP/FTPS","Disable anonymous access","Use chroot jail"],
        "smtp":["Enable SMTP auth","Implement SPF,DKIM,DMARC","Use TLS"],
        "mysql":["Never expose to internet","Bind to localhost only","Least privilege","Enable audit logging"],
        "postgresql":["Restrict via pg_hba.conf","Use SSL for remote connections","Enable query logging"],
        "rdp":["Enable NLA","Use VPN","Account lockout policy","Change default port 3389","Require MFA"],
        "smb":["Disable SMBv1 immediately","Enable SMB signing","Block ports 445/139"],
        "telnet":["DISABLE TELNET — plaintext protocol","Replace with SSH","Block port 23"],
        "vnc":["Never expose VNC publicly","Use VPN or SSH tunnel","Enable VNC password auth"],
        "redis":["Bind to localhost only","Enable AUTH password","Never expose publicly"],
        "mongodb":["Enable authentication","Bind to localhost","Use TLS","Enable audit logging"],
    }
    for svc,tips in svc_advice.items():
        if svc in sl or svc in pl: advice.extend(tips); break
    if not advice:
        advice=[f"Keep {product or service} updated","Apply principle of least privilege","Monitor service logs","Restrict to authorized hosts"]
    critical=[c for c in cves if c.get("severity") in ["CRITICAL","HIGH"]]
    if critical: advice.insert(0,f"URGENT: {len(critical)} critical/high CVEs — patch immediately")
    advice.extend(["Implement IDS/IPS monitoring","Schedule regular vulnerability scans"])
    return advice[:8]

def calculate_risk(cves,port,service):
    high_risk={21,22,23,25,80,443,445,1433,1521,3306,3389,5432,5900,6379,27017}
    base=0
    if cves:
        base=max((c.get("score") or 0) for c in cves)
        if any(c.get("has_exploit") for c in cves): base=min(10,base+1)
    elif port in high_risk: base=5.0
    else: base=2.0
    if service and service.lower()=="telnet": base=9.5
    if base>=9.0: level="CRITICAL"
    elif base>=7.0: level="HIGH"
    elif base>=4.0: level="MEDIUM"
    elif base>0: level="LOW"
    else: level="UNKNOWN"
    return round(base,1),level

# ─── FULL SCAN ORCHESTRATOR ───────────────────
def full_scan(target,modules=None):
    if modules is None: modules=["ports","ssl","dns","headers"]
    result={"target":target,"scan_time":datetime.utcnow().isoformat(),"modules":{}}
    scan=run_nmap_scan(target)
    if "error" not in scan:
        for host in scan.get("hosts",[]):
            for port in host.get("ports",[]):
                svc=port.get("service",""); prod=port.get("product",""); ver=port.get("version","")
                cves=[]
                if prod: cves=search_nvd_cves(prod,ver); time.sleep(0.4)
                if not cves and svc: cves=search_nvd_cves(svc,ver); time.sleep(0.4)
                port["cves"]=cves
                port["mitigations"]=get_mitigation_advice(svc,prod,cves)
                port["risk_score"],port["risk_level"]=calculate_risk(cves,port["port"],svc)
    result["modules"]["ports"]=scan
    clean=re.sub(r'https?://','',target).split('/')[0]
    if "ssl" in modules:
        ssl_ports=[443,8443,465,993,995]
        if "hosts" in scan:
            open_ports=[p["port"] for h in scan.get("hosts",[]) for p in h.get("ports",[])]
            ssl_ports=[p for p in ssl_ports if p in open_ports] or [443]
        result["modules"]["ssl"]=[analyze_ssl(clean,sp) for sp in ssl_ports[:2]]
    if "dns" in modules: result["modules"]["dns"]=dns_recon(clean)
    if "headers" in modules: result["modules"]["headers"]=analyze_web_headers(clean)
    all_cves=[c for h in scan.get("hosts",[]) for p in h.get("ports",[]) for c in p.get("cves",[])]
    result["summary"]={"total_cves":len(all_cves),
        "critical_cves":sum(1 for c in all_cves if c.get("severity")=="CRITICAL"),
        "high_cves":sum(1 for c in all_cves if c.get("severity")=="HIGH"),
        "exploitable":sum(1 for c in all_cves if c.get("has_exploit")),
        "open_ports":sum(len(h.get("ports",[])) for h in scan.get("hosts",[]))}
    return result

# ─── ENTRY POINT ──────────────────────────────
if __name__=="__main__":
    import os
    sys.stderr=open(os.devnull,'w')
    if len(sys.argv)<2:
        print(json.dumps({"error":"No target specified"})); sys.exit(1)

    if "--discover" in sys.argv:
        idx=sys.argv.index("--discover")
        print(json.dumps(network_discovery(sys.argv[idx+1]))); sys.exit(0)

    if "--subdomains" in sys.argv:
        idx=sys.argv.index("--subdomains")
        size=sys.argv[idx+2] if len(sys.argv)>idx+2 else "medium"
        print(json.dumps(subdomain_finder(sys.argv[idx+1],size))); sys.exit(0)

    if "--dirbust" in sys.argv:
        idx=sys.argv.index("--dirbust")
        size=sys.argv[idx+2] if len(sys.argv)>idx+2 else "small"
        exts=sys.argv[idx+3] if len(sys.argv)>idx+3 else "php,html,txt"
        print(json.dumps(dir_enum(sys.argv[idx+1],size,exts))); sys.exit(0)

    if "--brute-http" in sys.argv:
        idx=sys.argv.index("--brute-http")
        url=sys.argv[idx+1]
        users=sys.argv[idx+2].split(",")
        pwds=sys.argv[idx+3].split(",")
        uf=sys.argv[idx+4] if len(sys.argv)>idx+4 else "username"
        pf=sys.argv[idx+5] if len(sys.argv)>idx+5 else "password"
        print(json.dumps(brute_force_http(url,users,pwds,uf,pf))); sys.exit(0)

    if "--brute-ssh" in sys.argv:
        idx=sys.argv.index("--brute-ssh")
        host=sys.argv[idx+1]; port=sys.argv[idx+2]
        users=sys.argv[idx+3].split(","); pwds=sys.argv[idx+4].split(",")
        print(json.dumps(brute_force_ssh(host,port,users,pwds))); sys.exit(0)

    mods=["ports","ssl","dns","headers"]
    target=sys.argv[-1]
    if "--modules" in sys.argv:
        idx=sys.argv.index("--modules")
        mods=sys.argv[idx+1].split(",")
    print(json.dumps(full_scan(target,mods)))
