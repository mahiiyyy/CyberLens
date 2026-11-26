CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('INVESTIGATOR','ANALYST','ADMIN')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_no TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  priority TEXT NOT NULL,
  status TEXT NOT NULL,
  investigator_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES cases(id),
  sha256 TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  integrity TEXT NOT NULL,
  raw_storage_key TEXT NOT NULL,
  processed_analysis JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS iocs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID REFERENCES cases(id),
  value TEXT NOT NULL,
  kind TEXT NOT NULL,
  verdict TEXT NOT NULL,
  confidence NUMERIC
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ===== Investigation persistence, evidence, reputation, AI summaries =====
-- Existing tables are only altered additively. Legacy evidence columns become
-- nullable because evidence is now owned by a user/investigation, not only a case.
ALTER TABLE cases ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
ALTER TABLE evidence ALTER COLUMN case_id DROP NOT NULL;
ALTER TABLE evidence ALTER COLUMN raw_storage_key DROP NOT NULL;
ALTER TABLE evidence ALTER COLUMN integrity DROP NOT NULL;

CREATE TABLE IF NOT EXISTS investigations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
  reference TEXT NOT NULL,
  title TEXT NOT NULL,
  verdict TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  is_sample BOOLEAN NOT NULL DEFAULT FALSE,
  original_sha256 TEXT NOT NULL CHECK (original_sha256 ~ '^[a-f0-9]{64}$'),
  original_size INTEGER NOT NULL,
  input_kind TEXT NOT NULL,
  analysis JSONB NOT NULL,
  ai_summary JSONB,
  consent_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS investigations_user_created_idx ON investigations(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS investigations_case_idx ON investigations(case_id);

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS file_name TEXT;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS size_bytes INTEGER;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS content BYTEA;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;
ALTER TABLE evidence ADD COLUMN IF NOT EXISTS last_verified_ok BOOLEAN;
CREATE INDEX IF NOT EXISTS evidence_user_idx ON evidence(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS reputation_lookups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
  indicator TEXT NOT NULL,
  kind TEXT NOT NULL,
  provider TEXT NOT NULL,
  status TEXT NOT NULL,
  result JSONB,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS reputation_user_idx ON reputation_lookups(user_id, indicator, provider, checked_at DESC);

-- Audit rows must survive account removal for the log's own integrity, but must not
-- block it: the user reference is cleared instead of cascading.
DO $$ BEGIN
  ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;
  ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
EXCEPTION WHEN others THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS audit_logs_user_idx ON audit_logs(user_id, created_at DESC);
