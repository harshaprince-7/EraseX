-- Add status column to certificates table
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS status VARCHAR(255) DEFAULT 'completed';

-- Update existing records to have 'completed' status
UPDATE certificates SET status = 'completed' WHERE status IS NULL;