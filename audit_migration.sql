-- ================================================================
--  VulnScan Pro — Audit Log Schema Migration
--  Paste this into Supabase Dashboard → SQL Editor → Run
--  Safe to run multiple times (uses IF NOT EXISTS checks)
-- ================================================================
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='email')            THEN ALTER TABLE audit_log ADD COLUMN email            TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='role')             THEN ALTER TABLE audit_log ADD COLUMN role             TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='auth_method')      THEN ALTER TABLE audit_log ADD COLUMN auth_method      TEXT DEFAULT 'password'; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_browser')       THEN ALTER TABLE audit_log ADD COLUMN ua_browser       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_os')            THEN ALTER TABLE audit_log ADD COLUMN ua_os            TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='ua_device')        THEN ALTER TABLE audit_log ADD COLUMN ua_device        TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country')      THEN ALTER TABLE audit_log ADD COLUMN geo_country      TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_country_code') THEN ALTER TABLE audit_log ADD COLUMN geo_country_code TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_region')       THEN ALTER TABLE audit_log ADD COLUMN geo_region       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_city')         THEN ALTER TABLE audit_log ADD COLUMN geo_city         TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_isp')          THEN ALTER TABLE audit_log ADD COLUMN geo_isp          TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_proxy')     THEN ALTER TABLE audit_log ADD COLUMN geo_is_proxy     BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='geo_is_hosting')   THEN ALTER TABLE audit_log ADD COLUMN geo_is_hosting   BOOLEAN DEFAULT FALSE; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='session_id')       THEN ALTER TABLE audit_log ADD COLUMN session_id       TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='http_method')      THEN ALTER TABLE audit_log ADD COLUMN http_method      TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='endpoint')         THEN ALTER TABLE audit_log ADD COLUMN endpoint         TEXT;              END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='status_code')      THEN ALTER TABLE audit_log ADD COLUMN status_code      INTEGER;           END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='response_ms')      THEN ALTER TABLE audit_log ADD COLUMN response_ms      INTEGER;           END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='risk_score')       THEN ALTER TABLE audit_log ADD COLUMN risk_score       INTEGER DEFAULT 0; END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='audit_log' AND column_name='impossible_travel')THEN ALTER TABLE audit_log ADD COLUMN impossible_travel BOOLEAN DEFAULT FALSE; END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_risk    ON audit_log(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action  ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ip      ON audit_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_country ON audit_log(geo_country_code);

-- Verify: should show 20+ columns
SELECT column_name, data_type FROM information_schema.columns
WHERE table_name = 'audit_log' ORDER BY ordinal_position;
