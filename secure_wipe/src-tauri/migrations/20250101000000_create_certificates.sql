-- Create certificates table
CREATE TABLE certificates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    drive VARCHAR(255) NOT NULL,
    wipe_mode VARCHAR(100) NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    content TEXT NOT NULL,
    hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_certificates_user_id ON certificates(user_id);
CREATE INDEX idx_certificates_timestamp ON certificates(timestamp DESC);
CREATE INDEX idx_certificates_drive_timestamp ON certificates(drive, timestamp);
CREATE INDEX idx_certificates_hash ON certificates(hash);

-- Add unique constraint to prevent duplicate certificates
CREATE UNIQUE INDEX idx_certificates_unique ON certificates(user_id, drive, timestamp, hash);