-- Prompt 1: threat_iocs.threat_type is VARCHAR(100); long values fail with
-- "value too long for type character varying(100)" on PostgreSQL.
-- Widen it to TEXT so arbitrary threat_type strings insert cleanly.
-- Apply with: psql -d <db> -f migrations/001_alter_threat_iocs_threat_type.sql
ALTER TABLE threat_iocs ALTER COLUMN threat_type TYPE TEXT;
