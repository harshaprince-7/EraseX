-- Create open audit certificates table
CREATE TABLE IF NOT EXISTS audit_certificates (
    id SERIAL PRIMARY KEY,
    certificate_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    
    -- Certificate metadata
    version VARCHAR(10) NOT NULL DEFAULT '1.0',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Issuer information
    issuer_name VARCHAR(255) NOT NULL,
    issuer_ca VARCHAR(255) NOT NULL,
    issuer_public_key TEXT NOT NULL,
    issuer_accreditation TEXT,
    
    -- Wipe operation details
    device_id VARCHAR(255) NOT NULL,
    drives TEXT[] NOT NULL,
    wipe_method VARCHAR(100) NOT NULL,
    compliance_standard VARCHAR(255) NOT NULL,
    operator_name VARCHAR(255) NOT NULL,
    operation_location VARCHAR(255),
    operation_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Digital signature
    signature_algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-SHA256',
    digital_signature TEXT NOT NULL,
    signature_public_key TEXT NOT NULL,
    certificate_chain TEXT[],
    
    -- Timestamp authority
    tsa_authority VARCHAR(255),
    tsa_timestamp TIMESTAMP WITH TIME ZONE,
    tsa_token TEXT,
    tsa_signature TEXT,
    
    -- Compliance attestations (JSON array)
    compliance_attestations JSONB,
    
    -- Witness signatures (JSON array)
    witness_signatures JSONB DEFAULT '[]'::jsonb,
    
    -- Blockchain anchor (optional)
    blockchain_name VARCHAR(50),
    transaction_hash VARCHAR(255),
    block_number BIGINT,
    merkle_proof TEXT,
    
    -- Full certificate JSON
    full_certificate JSONB NOT NULL,
    
    -- Verification status
    is_verified BOOLEAN DEFAULT FALSE,
    verification_timestamp TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_certificate_id CHECK (certificate_id ~ '^[0-9a-f-]{36}$')
);

-- Create indexes for performance
CREATE INDEX idx_audit_certificates_user_id ON audit_certificates(user_id);
CREATE INDEX idx_audit_certificates_certificate_id ON audit_certificates(certificate_id);
CREATE INDEX idx_audit_certificates_device_id ON audit_certificates(device_id);
CREATE INDEX idx_audit_certificates_operation_timestamp ON audit_certificates(operation_timestamp);
CREATE INDEX idx_audit_certificates_compliance_standard ON audit_certificates(compliance_standard);

-- Create GIN index for JSON fields
CREATE INDEX idx_audit_certificates_full_certificate ON audit_certificates USING GIN (full_certificate);
CREATE INDEX idx_audit_certificates_compliance_attestations ON audit_certificates USING GIN (compliance_attestations);