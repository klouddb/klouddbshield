-- Drop backup compliance columns (legacy runs table migrations).
ALTER TABLE runs DROP COLUMN backup_compliance_json;
ALTER TABLE runs DROP COLUMN backup_compliance_scanned_at;
