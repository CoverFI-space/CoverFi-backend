CREATE TABLE IF NOT EXISTS email_mfa_authenticators (
  email_hash text PRIMARY KEY,
  secret_ciphertext text NOT NULL,
  secret_iv text NOT NULL,
  secret_tag text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT email_mfa_authenticators_status_check
    CHECK (status IN ('active', 'disabled'))
);

CREATE INDEX IF NOT EXISTS email_mfa_authenticators_status_idx
  ON email_mfa_authenticators (status, confirmed_at DESC);
