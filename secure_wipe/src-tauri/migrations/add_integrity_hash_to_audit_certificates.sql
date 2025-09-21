-- Add integrity hash column to audit certificates table
ALTER TABLE audit_certificates ADD COLUMN IF NOT EXISTS integrity_hash VARCHAR(64);