-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- Schema 036_dlp: Admin-configurable DLP pattern defaults (Phase 36).
-- Stored in system_config as a JSON array, editable via admin UI.
-- dlp_check() reads these in addition to the dlp_policies table.
INSERT INTO system_config (key, value, description) VALUES (
  'dlp_patterns',
  '[
    {"name": "Credit Card Number", "regex": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b", "severity": "critical", "enabled": true},
    {"name": "SSN (US Social Security)", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b", "severity": "high", "enabled": true},
    {"name": "IBAN (Bank Account)", "regex": "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b", "severity": "medium", "enabled": true},
    {"name": "Passport Number", "regex": "\\b[A-Z0-9]{6,9}\\b", "severity": "medium", "enabled": false},
    {"name": "API Key / Secret", "regex": "\\b(?:sk-|api-|key-|secret-)[A-Za-z0-9_\\-]{20,}\\b", "severity": "critical", "enabled": true},
    {"name": "Chinese Resident ID (18-digit)", "regex": "\\b[1-9]\\d{5}(?:19|20)\\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]\\b", "severity": "high", "enabled": true},
    {"name": "Chinese Phone Number", "regex": "\\b1[3-9]\\d{9}\\b", "severity": "low", "enabled": true},
    {"name": "Chinese Business License", "regex": "\\b[0-9A-HJ-NPQRTUWXY]{2}\\d{5}[0-9A-HJ-NPQRTUWXY]{10}\\b", "severity": "low", "enabled": true}
  ]'::JSONB,
  'DLP pattern rules: array of {name, regex, severity: critical|high|medium|low, enabled}'
) ON CONFLICT (key) DO NOTHING;
