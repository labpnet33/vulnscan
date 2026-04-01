import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://qonplkgabhubntfhtthu.supabase.co")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_ANON_KEY = os.environ.get(
    "SUPABASE_ANON_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFvbnBsa2dhYmh1Ym50Zmh0dGh1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzUwMTc5MDMsImV4cCI6MjA5MDU5MzkwM30.oVFsJVBl4pD4Geq-Bj4X4m-HOe-wSctbfSPNaNq32ak"
)

def get_client():
    try:
        from supabase import create_client
    except ImportError:
        raise RuntimeError("Run: pip3 install supabase --break-system-packages")
    key = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
    return create_client(SUPABASE_URL, key)

_client = None

def supabase():
    global _client
    if _client is None:
        _client = get_client()
    return _client
