#!/usr/bin/env python3
import os, shutil
from datetime import datetime

FILE = "api_server.py"

def backup():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(FILE, f"{FILE}.{ts}.bak")

def patch():
    if not os.path.exists(FILE):
        print("❌ api_server.py not found")
        return

    backup()

    with open(FILE, "r", encoding="utf-8") as f:
        data = f.read()

    # ✅ ONLY enhance placeholder (SAFE)
    data = data.replace(
        'placeholder="--help"',
        'placeholder="-u https://example.com -w /usr/share/wordlists/dirb/common.txt"'
    )

    # ✅ ensure all buttons use generic function
    data = data.replace("runFfuf()", "runGenericTool('ffuf','ffuf')")
    data = data.replace("runNuclei()", "runGenericTool('nuclei','nuclei')")
    data = data.replace("runWhatWeb()", "runGenericTool('whatweb','whatweb')")
    data = data.replace("runWapiti()", "runGenericTool('wapiti','wapiti')")

    with open(FILE, "w", encoding="utf-8") as f:
        f.write(data)

    print("✅ Safe patch applied")

if __name__ == "__main__":
    patch()
