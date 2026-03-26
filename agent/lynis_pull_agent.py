#!/usr/bin/env python3
"""
VulnScan Lynis Pull Agent
Runs on customer Linux host, polls VulnScan server for Lynis jobs, runs scan locally, uploads result.
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def http_json(url, method="GET", payload=None, token=""):
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ensure_lynis():
    if shutil.which("lynis"):
        return True
    apt = shutil.which("apt-get")
    if not apt:
        return False
    try:
        subprocess.run(["sudo", apt, "update"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", apt, "install", "-y", "lynis"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False
    return bool(shutil.which("lynis"))


def parse_lynis_output(output):
    hardening_index = 0
    warnings, suggestions = [], []
    tests_performed = "?"
    for line in output.splitlines():
        m = re.search(r"Hardening index\s*[:\|]\s*(\d+)", line, re.IGNORECASE)
        if m:
            hardening_index = int(m.group(1))
        tm = re.search(r"Tests performed\s*[:\|]\s*(\d+)", line, re.IGNORECASE)
        if tm:
            tests_performed = tm.group(1)
        if "warning" in line.lower():
            warnings.append(line.strip())
        if "suggestion" in line.lower():
            suggestions.append(line.strip())
    return {
        "hardening_index": hardening_index,
        "warnings": warnings[:80],
        "suggestions": suggestions[:120],
        "tests_performed": tests_performed,
        "raw_report": output[-200000:],
    }


def parse_lynis_report_dat(content):
    hardening_index = 0
    warnings, suggestions = [], []
    tests_performed = "?"
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("hardening_index="):
            try:
                hardening_index = int(line.split("=", 1)[1].strip())
            except Exception:
                pass
        elif line.startswith("tests_performed="):
            tests_performed = line.split("=", 1)[1].strip() or tests_performed
        elif line.startswith("warning[]="):
            warnings.append(line.split("=", 1)[1].strip())
        elif line.startswith("suggestion[]="):
            suggestions.append(line.split("=", 1)[1].strip())
    return {
        "hardening_index": hardening_index,
        "warnings": warnings,
        "suggestions": suggestions,
        "tests_performed": tests_performed,
    }


def run_job(job, api_base, token):
    job_id = job["job_id"]
    http_json(f"{api_base}/api/jobs/{job_id}/progress", method="POST",
              payload={"progress_pct": 10, "message": "Preparing Lynis"}, token=token)
    if not ensure_lynis():
        raise RuntimeError("Lynis not installed and auto-install failed. Install with: sudo apt install lynis")
    with tempfile.TemporaryDirectory(prefix="vulnscan-lynis-") as tmpdir:
        report_file = os.path.join(tmpdir, "lynis-report.dat")
        log_file = os.path.join(tmpdir, "lynis.log")
        cmd = [
            "lynis", "audit", "system", "--quiet", "--no-colors", "--noplugins",
            "--report-file", report_file, "--logfile", log_file
        ]
        if job.get("compliance"):
            cmd += ["--compliance", str(job["compliance"]).lower()]
        http_json(f"{api_base}/api/jobs/{job_id}/progress", method="POST",
                  payload={"progress_pct": 40, "message": "Lynis running"}, token=token)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=420)
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        parsed = parse_lynis_output(out)
        report_dat_content = ""
        if os.path.exists(report_file):
            with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                report_dat_content = f.read()
            dat_parsed = parse_lynis_report_dat(report_dat_content)
            parsed["hardening_index"] = dat_parsed["hardening_index"] or parsed["hardening_index"]
            parsed["warnings"] = sorted(set(parsed["warnings"] + dat_parsed["warnings"]))[:120]
            parsed["suggestions"] = sorted(set(parsed["suggestions"] + dat_parsed["suggestions"]))[:200]
            if parsed["tests_performed"] in {"", "?", None}:
                parsed["tests_performed"] = dat_parsed["tests_performed"]
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                out += "\n\n# lynis.log\n" + f.read()
        if report_dat_content:
            out += "\n\n# lynis-report.dat\n" + report_dat_content
        parsed["raw_report"] = out[-200000:]
    http_json(f"{api_base}/api/upload", method="POST", payload={"job_id": job_id, **parsed}, token=token)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api-base", required=True, help="Example: http://your-server:5000")
    p.add_argument("--client-id", required=True, help="Unique id for this machine")
    p.add_argument("--token", default="", help="Agent token; if omitted, agent will register and print one")
    p.add_argument("--interval", type=int, default=30)
    args = p.parse_args()

    api_base = args.api_base.rstrip("/")
    token = args.token.strip()
    if not token:
        reg = http_json(f"{api_base}/api/agent/register", method="POST", payload={
            "client_id": args.client_id,
            "hostname": socket.gethostname(),
            "os_info": f"{platform.system()} {platform.release()}",
        })
        token = reg["token"]
        print(f"[+] Registered agent {args.client_id}")
        print(f"[+] Save token securely: {token}")
        print("[+] Continuing in connected mode with generated token.")

    print(f"[*] Agent started for {args.client_id}, polling every {args.interval}s")
    while True:
        try:
            job = http_json(f"{api_base}/api/jobs", token=token)
            if job.get("type") == "lynis" and job.get("job_id"):
                print(f"[*] Running Lynis job #{job['job_id']}")
                run_job(job, api_base, token)
                print(f"[+] Job #{job['job_id']} completed")
        except urllib.error.HTTPError as e:
            print(f"[!] HTTP error: {e.code} {e.reason}")
            if e.code in (401, 403):
                print("[!] Agent token is no longer valid (likely disconnected from dashboard).")
                print("[!] Re-run the install curl command to reconnect this system.")
                break
        except Exception as e:
            print(f"[!] Agent loop error: {e}")
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    main()
