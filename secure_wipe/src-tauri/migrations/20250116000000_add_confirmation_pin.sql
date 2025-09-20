-- Add confirmation_pin column to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS confirmation_pin VARCHAR(10);

-- Create index for faster PIN lookups
CREATE INDEX IF NOT EXISTS idx_users_confirmation_pin ON users(confirmation_pin);