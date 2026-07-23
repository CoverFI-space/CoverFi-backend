CREATE TABLE IF NOT EXISTS email_wallet_otps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_hash text NOT NULL,
  nonce text NOT NULL,
  otp_hash text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  CONSTRAINT email_wallet_otps_status_check
    CHECK (status IN ('pending', 'verified', 'expired', 'locked'))
);

CREATE INDEX IF NOT EXISTS email_wallet_otps_lookup_idx
  ON email_wallet_otps (email_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS email_wallet_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email_hash text NOT NULL,
  wallet_ref text NOT NULL,
  wallet_address text NOT NULL,
  network text NOT NULL,
  funding_status text NOT NULL DEFAULT 'created_unfunded',
  funding_source text,
  funding_transaction_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  funded_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (email_hash, wallet_address, network),
  CONSTRAINT email_wallet_accounts_network_check
    CHECK (network IN ('testnet', 'mainnet')),
  CONSTRAINT email_wallet_accounts_funding_status_check
    CHECK (funding_status IN ('created_unfunded', 'friendbot_pending', 'friendbot_funded', 'friendbot_failed', 'sponsored_funded'))
);

CREATE INDEX IF NOT EXISTS email_wallet_accounts_email_idx
  ON email_wallet_accounts (email_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS email_wallet_accounts_wallet_ref_idx
  ON email_wallet_accounts (wallet_ref, created_at DESC);

CREATE TABLE IF NOT EXISTS zk_commitments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_ref text NOT NULL,
  commitment text NOT NULL,
  commitment_scheme text NOT NULL DEFAULT 'sha256-v0',
  circuit_id text NOT NULL,
  public_signals jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  UNIQUE (commitment),
  CONSTRAINT zk_commitments_status_check
    CHECK (status IN ('active', 'revoked', 'expired'))
);

CREATE INDEX IF NOT EXISTS zk_commitments_subject_idx
  ON zk_commitments (subject_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS zk_commitments_circuit_idx
  ON zk_commitments (circuit_id, created_at DESC);

CREATE TABLE IF NOT EXISTS zk_proof_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_ref text,
  commitment_id uuid REFERENCES zk_commitments(id) ON DELETE SET NULL,
  circuit_id text NOT NULL,
  proof_system text NOT NULL,
  proof_hash text NOT NULL,
  public_signals jsonb NOT NULL DEFAULT '{}'::jsonb,
  verification_status text NOT NULL,
  verifier text NOT NULL DEFAULT 'coverfi-backend',
  verifier_notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT zk_proof_events_status_check
    CHECK (verification_status IN ('recorded', 'verified', 'unsupported', 'failed'))
);

CREATE INDEX IF NOT EXISTS zk_proof_events_subject_idx
  ON zk_proof_events (subject_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS zk_proof_events_circuit_idx
  ON zk_proof_events (circuit_id, created_at DESC);
