-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V058: Seed RBAC permissions and builtin role groups
BEGIN;

-- ── Permissions ──────────────────────────────────────────────────────────

INSERT INTO admin_permissions (permission_key, category, description, is_sensitive) VALUES
('users.read',              'Users',    'View users, profiles, aliases',                false),
('users.write',             'Users',    'Create, update, suspend users',                 false),
('users.delete',            'Users',    'Permanently delete users',                      true),
('users.password_reset',    'Users',    'Reset non-admin passwords',                     false),
('users.impersonate',       'Users',    'Impersonate another user mailbox',              true),
('domains.read',            'Domains',  'View domain configuration',                     false),
('domains.write',           'Domains',  'Add/remove domains, change DNS config',         true),
('audit.read',              'Audit',    'View audit logs, login history',                false),
('mam.read',                'MAM',      'View MAM policies, device list, events',        false),
('mam.write',               'MAM',      'Change policies, lock/wipe devices',            true),
('queue.read',              'Queue',    'View outbound queue status',                    false),
('queue.write',             'Queue',    'Retry, bounce, purge queue items',              false),
('reports.read',            'Reports',  'View storage, traffic, user activity reports',  false),
('security.write',          'Security', 'Threat settings, TLS config, spam threshold',   true),
('roles.manage',            'Roles',    'Create/edit/delete role groups',                true),
('compliance.read',         'Compliance','View eDiscovery, retention policies, DLP',     false),
('compliance.write',        'Compliance','Create eDiscovery cases, edit policies',       true),
('backup.read',             'Backup',   'View backup status, restore history',           false),
('backup.write',            'Backup',   'Trigger backup, initiate restore',              true),
('system.config',           'System',   'Change gateway config, feature toggles',        true),
('system.upgrade',          'System',   'Trigger software upgrade',                      true)
ON CONFLICT (permission_key) DO NOTHING;

-- ── Builtin Role Groups ──────────────────────────────────────────────────

-- Super Admin: all permissions
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('Super Admin', 'Full unrestricted access to all admin features.',
 ARRAY(SELECT permission_key FROM admin_permissions), NULL, true)
ON CONFLICT (name) DO NOTHING;

-- User Admin
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('User Admin', 'Manage users and view domains. Cannot change server settings.',
 ARRAY['users.read','users.write','users.password_reset','domains.read','audit.read'], NULL, true)
ON CONFLICT (name) DO NOTHING;

-- Help Desk
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('Help Desk', 'Reset passwords, view users, manage mail queue.',
 ARRAY['users.read','users.password_reset','queue.read','queue.write'], NULL, true)
ON CONFLICT (name) DO NOTHING;

-- Audit Reader
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('Audit Reader', 'Read-only access to audit logs and reports.',
 ARRAY['audit.read','reports.read'], NULL, true)
ON CONFLICT (name) DO NOTHING;

-- Security Admin
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('Security Admin', 'Manage MAM policies, security settings. Cannot manage users.',
 ARRAY['mam.read','mam.write','security.write','audit.read','users.read'], NULL, true)
ON CONFLICT (name) DO NOTHING;

-- Domain Admin
INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin) VALUES
('Domain Admin', 'Manage users and view reports for a specific domain. Domain scope required.',
 ARRAY['users.read','users.write','users.password_reset','domains.read','audit.read','reports.read'], NULL, true)
ON CONFLICT (name) DO NOTHING;

COMMIT;
