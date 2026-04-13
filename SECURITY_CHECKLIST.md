# VulnScan Pro — Post-Patch Security Checklist
# ================================================
# Complete these MANUAL steps after running the patch script.

## ━━━ IMMEDIATE — Do Within the Next 30 Minutes ━━━

### [CRITICAL-0] Rotate ALL exposed credentials

# 1. Supabase — revoke and regenerate keys:
#    https://supabase.com/dashboard/project/qonplkgabhubntfhtthu/settings/api
#    - Click "Reset service_role key"
#    - Click "Reset anon key"
#    - Update .env with new values

# 2. Gmail App Password — revoke and create new:
#    https://myaccount.google.com/apppasswords
#    - Delete "hkls wpey nvxi bgwh"
#    - Create new app password
#    - Update VULNSCAN_SMTP_PASS in .env

# 3. Flask secret — generate new random key:
python3 -c "import secrets; print(secrets.token_hex(64))"
#    Update VULNSCAN_SECRET in .env

# 4. Ensure .env is NOT in git history:
git rm --cached .env 2>/dev/null || true
grep -q ".env" .gitignore || echo ".env" >> .gitignore
git log --all --full-history -- .env   # check if ever committed
# If it was committed: git filter-repo --path .env --invert-paths

## ━━━ TODAY ━━━

### [HIGH-H3] Enable HTTPS with a real TLS certificate

# Option A — Nginx reverse proxy + Let's Encrypt (recommended):
sudo apt install nginx certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
# Then proxy to Flask on 127.0.0.1:5000

# After HTTPS is working, set in .env:
echo "VULNSCAN_HTTPS=true" >> .env

# Option B — Cloudflare Tunnel (zero config):
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/

### [HIGH-H5] Restrict agent registration to known clients

# In api_server.py, add a pre-shared agent registration secret.
# Set in .env:
echo "VULNSCAN_AGENT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env
# Agent installs must pass this secret in the registration payload.

### [MEDIUM-M3] Fix Supabase Row-Level Security policies

# In Supabase dashboard → Authentication → Policies:
# Ensure users table RLS policies exist:
#   - Users can only read/update their OWN row
#   - Only service_role can read all users (for admin functions)
#   - No policy should allow anon key to read password_hash column

# Run in Supabase SQL editor:
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_own_row" ON users
  FOR SELECT USING (auth.uid()::text = id::text);
-- Admin reads via service_role bypass RLS automatically.

## ━━━ THIS WEEK ━━━

### [MEDIUM] Add nginx rate limiting

# /etc/nginx/sites-enabled/vulnscan:
# limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
# location /api/login { limit_req zone=login burst=3 nodelay; }

### [LOW-L3] Migrate to Argon2 password hashing (gradual)
# pip3 install argon2-cffi --break-system-packages
# Update hash_password() in auth.py to use argon2-cffi
# Add migration: on next login, rehash PBKDF2 → Argon2

### [MEDIUM] Add request logging to detect attacks
# pip3 install flask-wtf --break-system-packages
# Log all 400/401/403/429 responses with IP, user agent, path

### [LOW] Set up fail2ban for SSH and the web app
# /etc/fail2ban/filter.d/vulnscan.conf:
# [Definition]
# failregex = .* LOGIN_FAIL .* ip=<HOST>
# [vulnscan]
# enabled = true
# filter = vulnscan
# logpath = /var/log/vulnscan.log
# maxretry = 5
# bantime = 3600

## ━━━ ENVIRONMENT VARIABLES REFERENCE ━━━

# Required in .env after credential rotation:
# VULNSCAN_SECRET=<new 64-char hex>
# SUPABASE_URL=https://qonplkgabhubntfhtthu.supabase.co
# SUPABASE_ANON_KEY=<new anon key>
# SUPABASE_SERVICE_KEY=<new service key>
# VULNSCAN_SMTP_PASS=<new app password without spaces>
# VULNSCAN_HTTPS=true   (after TLS setup)
# VULNSCAN_AGENT_SECRET=<random secret for agent registration>
# VULNSCAN_MAX_TOOLS=3  (from performance patch)
