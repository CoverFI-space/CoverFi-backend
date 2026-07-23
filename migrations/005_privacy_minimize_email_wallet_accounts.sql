ALTER TABLE email_wallet_accounts
  ALTER COLUMN wallet_address DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS email_wallet_accounts_email_wallet_ref_network_idx
  ON email_wallet_accounts (email_hash, wallet_ref, network);
