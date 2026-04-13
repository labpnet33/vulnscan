import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")

def get_client():
    try:
        from supabase import create_client
    except ImportError:
        raise RuntimeError("Run: pip3 install supabase --break-system-packages")
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not configured")
    key = SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY
    if not key:
        raise RuntimeError("SUPABASE_SERVICE_KEY or SUPABASE_ANON_KEY must be configured")
    return create_client(SUPABASE_URL, key)

_client = None

def supabase():
    global _client
    if _client is None:
        _client = get_client()
    return _client

def reset_client():
    global _client
    _client = None
