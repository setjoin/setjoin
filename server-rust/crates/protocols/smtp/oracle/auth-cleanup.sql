-- Assigned disposable database only; no external or global fixture deletion.
DELETE FROM dmarc_reports WHERE domain='smtp2.test' OR domain LIKE '%.smtp2.test';
