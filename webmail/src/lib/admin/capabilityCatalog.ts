import type { ConsoleId } from "$lib/admin/consoles";

/**
 * One entry per DISTINCT admin permission. The Access Preview
 * renders these as the user's capabilities (✓/✗ + granting role), grouped by
 * console → page. Multiple admin buttons sharing a perm are ONE capability here.
 *
 * The drift guard (capabilityCatalog.test.ts) asserts this set covers every
 * `hasPermission($adminPermissions, '<perm>')` gate in the admin UI, so a new
 * gated control on a new perm fails CI until it's catalogued. console/page are
 * for display grouping only.
 */
export interface CapabilityCap {
  perm: string;
  label: string;
  console: ConsoleId;
  page: string;
}

export const CAPABILITIES: CapabilityCap[] = [
  ...([
    ["exchange.assessment.read", "View masked Exchange replacement assessments"],
    ["exchange.assessment.run", "Run and import Exchange assessments"],
    ["exchange.assessment.decide", "Decide Exchange capability mappings"],
    ["exchange.assessment.attest", "Attest Exchange assessment evidence"],
    ["exchange.assessment.audit", "Audit raw Exchange assessment evidence"],
    ["exchange.assessment.publish", "Publish evidence-derived Exchange claims"],
    ["exchange.assessment.delete", "Request Exchange assessment deletion"],
  ] as const).map(([perm, label]) => ({ perm, label, console: "mail" as ConsoleId, page: "Exchange replacement" })),
  {
    perm: "users.create",
    label: "Create users, mailboxes & departments",
    console: "auth",
    page: "Users",
  },
  {
    perm: "users.suspend",
    label: "Edit & suspend users",
    console: "auth",
    page: "Users",
  },
  {
    perm: "users.delete",
    label: "Delete users",
    console: "auth",
    page: "Users",
  },
  {
    perm: "users.password_reset",
    label: "Reset user passwords",
    console: "auth",
    page: "Users",
  },
  {
    perm: "users.impersonate",
    label: "Impersonate (view as user)",
    console: "auth",
    page: "Users",
  },
  {
    perm: "domains.write",
    label: "Manage domains",
    console: "mail",
    page: "Domains",
  },
  {
    perm: "queue.write",
    label: "Retry / bounce the mail queue",
    console: "mail",
    page: "Queue",
  },
  {
    perm: "mail.pipeline",
    label: "Mail rules & migration",
    console: "mail",
    page: "Rules / Migration",
  },
  {
    perm: "mail.security",
    label: "DLP patterns",
    console: "mail",
    page: "DLP",
  },
  {
    perm: "security.write",
    label: "Quarantine, spam, TLS, alerts & threat rules",
    console: "mail",
    page: "Security",
  },
  {
    perm: "compliance.write",
    label: "Retention, eDiscovery & content search",
    console: "mail",
    page: "Compliance",
  },
  {
    perm: "system.config",
    label: "System settings, features, webhooks & storage",
    console: "system",
    page: "System",
  },
  {
    perm: "system.upgrade",
    label: "System upgrade & deploy",
    console: "system",
    page: "System",
  },
  {
    perm: "system.recovery",
    label: "Client-assisted mail recovery",
    console: "access",
    page: "Recovery",
  },
  {
    perm: "backup.write",
    label: "Backups",
    console: "system",
    page: "Backups",
  },
  {
    perm: "mam.write",
    label: "Mobile device management (MAM/MDM)",
    console: "system",
    page: "Mobile devices",
  },
  {
    perm: "identity.write",
    label: "Identity config (auth methods, AD/LDAP, conditional access)",
    console: "auth",
    page: "Identity",
  },
  {
    perm: "roles.manage",
    label: "Manage roles & assignments",
    console: "access",
    page: "Roles",
  },
  {
    perm: "scope_sets.manage",
    label: "Manage scope-sets",
    console: "access",
    page: "Scope sets",
  },
  {
    perm: "guests.view",
    label: "View guest accounts and profiles",
    console: "access",
    page: "Guests",
  },
  {
    perm: "guests.manage",
    label: "Manage guest accounts and profiles",
    console: "access",
    page: "Guests",
  },
  {
    perm: "approvals.view",
    label: "View approval requests (audit read)",
    console: "access",
    page: "Approvals",
  },
  {
    perm: "approvals.manage",
    label: "Manage approval policies",
    console: "access",
    page: "Approvals",
  },
  {
    perm: "sharing.read",
    label: "View sharing defaults & audit",
    console: "access",
    page: "Sharing",
  },
  {
    perm: "sharing.manage",
    label: "Manage sharing defaults & overrides",
    console: "access",
    page: "Sharing",
  },
  {
    perm: "drive.view",
    label: "View drive spaces (active checkouts)",
    console: "system",
    page: "Drive",
  },
  {
    perm: "drive.manage",
    label: "Break drive checkouts",
    console: "system",
    page: "Drive",
  },
  {
    perm: "office.view",
    label: "View Office provider policy and health",
    console: "system",
    page: "Office",
  },
  {
    perm: "office.manage",
    label: "Manage Office providers and routing",
    console: "system",
    page: "Office",
  },
  {
    perm: "apps.view",
    label: "View curated application runtime and operations",
    console: "system",
    page: "Applications",
  },
  {
    perm: "apps.manage",
    label: "Install and manage curated application runtimes",
    console: "system",
    page: "Applications",
  },
  {
    perm: "chat.compliance_view",
    label: "View chat retention, holds & audit",
    console: "access",
    page: "Chat compliance",
  },
  {
    perm: "chat.compliance_manage",
    label: "Manage chat retention, holds & classification",
    console: "access",
    page: "Chat compliance",
  },
  {
    perm: "chat.ediscovery",
    label: "Search, read & export chat for eDiscovery",
    console: "access",
    page: "Chat compliance",
  },
  {
    perm: "federation.manage",
    label: "Manage the cross-org federation allow-list & trust anchors",
    console: "access",
    page: "Federation",
  },
];
