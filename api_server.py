#!/usr/bin/env python3
"""
Flask API Server for VulnScan
Bridges the React frontend with the nmap backend scanner
Run: pip install flask flask-cors && python3 api_server.py
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import sys
import os

app = Flask(__name__)
CORS(app)  # Allow requests from localhost React dev server

BACKEND_SCRIPT = os.path.join(os.path.dirname(__file__), "backend.py")


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "GET":
        target = request.args.get("target", "").strip()
    else:
        data = request.get_json() or {}
        target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target specified"}), 400

    # Basic validation - prevent command injection
    import re
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$', target):
        return jsonify({"error": "Invalid target format"}), 400

    try:
        result = subprocess.run(
            [sys.executable, BACKEND_SCRIPT, target],
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.stdout:
            data = json.loads(result.stdout)
            return jsonify(data)
        else:
            return jsonify({"error": result.stderr or "Scan produced no output"}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out"}), 504
    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse scan output"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "VulnScan API is running"})


if __name__ == "__main__":
    print("[*] VulnScan API Server starting on http://localhost:5000")
    print("[*] Make sure nmap is installed: sudo apt-get install nmap")
    print("[*] CORS enabled for React dev server")
    app.run(host="0.0.0.0", port=5000, debug=False)
