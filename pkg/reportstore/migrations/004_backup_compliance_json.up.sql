-- Add backup compliance columns (legacy runs table migrations).
ALTER TABLE runs ADD COLUMN backup_compliance_json JSON;
ALTER TABLE runs ADD COLUMN backup_compliance_scanned_at TEXT;
