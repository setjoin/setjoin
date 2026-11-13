/**
 * Console model — single source of truth for the five RBAC-gated admin
 * consoles and their navigation items. Mirrors the Go admin.ConsoleID
 * values returned in /jmap/session capabilities.
 *
 * Console IDs match the Go admin.ConsoleID constants exactly so that the
 * session's `admin.consoles` string[] can be used directly with
 * navForConsoles().
 */

import type { IconName } from "$lib/components/Icon.svelte";

/** Matches Go admin.ConsoleID constants returned in /jmap/session. */
export type ConsoleId = "mail" | "system" | "logs" | "auth" | "access";

export interface ConsoleNavItem {
  /** i18n key for the sidebar label. */
  label: string;
  /** Route path (must start with /admin). */
  path: string;
  /** Lucide icon name as imported in Icon.svelte. */
  icon: IconName;
  /**
   * Optional permission gate. When set, the nav item only renders for callers
   * whose resolved permission set includes it (the page + backend still gate).
   * Used for Super-only surfaces inside a console the caller can otherwise see.
   */
  /** One permission, or an any-of list for read/manage sibling grants. */
  perm?: string | readonly string[];
}

export interface ConsoleDef {
  id: ConsoleId;
  /** i18n key for the console name (rail tooltip, drawer label). */
  label: string;
  /** Lucide icon name for the rail button. */
  icon: IconName;
  items: ConsoleNavItem[];
}

/**
 * The five admin consoles in declared order (matching Go's declaredOrder).
 * Every existing admin route is assigned to exactly one console.
 */
export const CONSOLES: ConsoleDef[] = [
  {
    id: "mail",
    icon: "ServerCog",
    label: "admin.console.mail",
    items: [
      { label: "admin.sidebar.dashboard", path: "/admin", icon: "LayoutGrid" },
      {
        label: "admin.sidebar.queue",
        path: "/admin/queue",
        icon: "ListOrdered",
      },
      {
        label: "admin.sidebar.background_jobs",
        path: "/admin/background-jobs",
        icon: "ListChecks",
      },
      { label: "admin.sidebar.domains", path: "/admin/domains", icon: "Link" },
      {
        label: "admin.sidebar.mailboxes",
        path: "/admin/mailboxes",
        icon: "Inbox",
      },
      {
        label: "admin.sidebar.departments",
        path: "/admin/departments",
        icon: "Building2",
      },
      {
        label: "admin.sidebar.quarantine",
        path: "/admin/quarantine",
        icon: "Shield",
      },
      { label: "admin.sidebar.dmarc", path: "/admin/dmarc", icon: "FileText" },
      { label: "admin.sidebar.dns", path: "/admin/dns", icon: "Link" },
      { label: "admin.sidebar.tls", path: "/admin/tls", icon: "Key" },
      { label: "admin.sidebar.spam", path: "/admin/spam", icon: "Shield" },
      {
        label: "admin.sidebar.retention",
        path: "/admin/retention",
        icon: "Archive",
      },
      {
        label: "admin.sidebar.storage",
        path: "/admin/storage",
        icon: "HardDrive",
      },
      {
        label: "admin.sidebar.rules",
        path: "/admin/rules",
        icon: "ScrollText",
      },
      {
        label: "admin.sidebar.migration",
        path: "/admin/migration",
        icon: "Package",
      },
      {
        label: "admin.sidebar.exchange_replacement",
        path: "/admin/exchange-replacement",
        icon: "FileSearch",
        perm: "exchange.assessment.read",
      },
      {
        label: "admin.sidebar.reports",
        path: "/admin/reports",
        icon: "BarChart3",
      },
      { label: "admin.sidebar.trace", path: "/admin/trace", icon: "Search" },
      {
        label: "admin.sidebar.ediscovery",
        path: "/admin/ediscovery",
        icon: "FileSearch",
      },
      {
        label: "admin.sidebar.content_search",
        path: "/admin/content-search",
        icon: "Search",
      },
      {
        label: "admin.sidebar.mam_devices",
        path: "/admin/mam/devices",
        icon: "MonitorSmartphone",
      },
      {
        label: "admin.sidebar.mam_policies",
        path: "/admin/mam/policies",
        icon: "FileText",
      },
      {
        label: "admin.sidebar.email_address_policies",
        path: "/admin/email-address-policies",
        icon: "Mail",
      },
      {
        label: "admin.sidebar.smime_trust",
        path: "/admin/smime-trust",
        icon: "ShieldCheck",
      },
    ],
  },
  {
    id: "system",
    icon: "Cpu",
    label: "admin.console.system",
    items: [
      { label: "admin.sidebar.system", path: "/admin/system", icon: "Cpu" },
      {
        label: "admin.sidebar.welcome_email",
        path: "/admin/system/welcome-email",
        icon: "Mail",
      },
      {
        label: "admin.sidebar.offline",
        path: "/admin/offline",
        icon: "CloudOff",
      },
      { label: "admin.sidebar.deploy", path: "/admin/deploy", icon: "Package" },
      {
        label: "admin.sidebar.features",
        path: "/admin/features",
        icon: "ToggleLeft",
      },
      {
        label: "admin.sidebar.office",
        path: "/admin/office",
        icon: "FileText",
        perm: ["office.view", "office.manage"],
      },
      {
        label: "admin.sidebar.apps",
        path: "/admin/apps",
        icon: "Boxes",
        perm: ["apps.view", "apps.manage"],
      },
      {
        label: "admin.sidebar.updates",
        path: "/admin/updates",
        icon: "RefreshCw",
      },
      { label: "admin.sidebar.logs", path: "/admin/logs", icon: "ScrollText" },
      {
        label: "admin.sidebar.webhooks",
        path: "/admin/webhooks",
        icon: "Link",
      },
    ],
  },
  {
    id: "logs",
    icon: "ScrollText",
    label: "admin.console.logs",
    items: [
      {
        label: "admin.sidebar.threats",
        path: "/admin/threats",
        icon: "Shield",
      },
      {
        label: "admin.sidebar.audit",
        path: "/admin/audit",
        icon: "FileSearch",
      },
      {
        label: "admin.sidebar.alerts",
        path: "/admin/alerts",
        icon: "BellRing",
      },
      { label: "admin.sidebar.auth_log", path: "/admin/auth-log", icon: "Key" },
    ],
  },
  {
    id: "auth",
    icon: "ShieldCheck",
    label: "admin.console.auth",
    items: [
      { label: "admin.sidebar.users", path: "/admin/users", icon: "Users" },
      {
        label: "admin.sidebar.conditional_access",
        path: "/admin/conditional-access",
        icon: "Shield",
      },
      { label: "admin.sidebar.identity", path: "/admin/identity", icon: "Key" },
      {
        label: "admin.sidebar.device_lockdown",
        path: "/admin/device-lockdown",
        icon: "Fingerprint",
      },
      {
        label: "admin.sidebar.terms_of_use",
        path: "/admin/terms-of-use",
        icon: "FileText",
      },
    ],
  },
  {
    id: "access",
    icon: "Key",
    label: "admin.console.access",
    items: [
      {
        label: "admin.jit.my_roles_title",
        path: "/admin/my-roles",
        icon: "Moon",
      },
      { label: "admin.sidebar.roles", path: "/admin/roles", icon: "Key" },
      {
        label: "admin.sidebar.recovery",
        path: "/admin/recovery",
        icon: "RotateCcw",
        perm: "system.recovery",
      },
      {
        label: "admin.sidebar.guests",
        path: "/admin/guests",
        icon: "Users",
        perm: ["guests.view", "guests.manage"],
      },
      {
        label: "admin.sidebar.user_risk",
        path: "/admin/user-risk",
        icon: "AlertTriangle",
      },
      {
        label: "admin.sidebar.scope_sets",
        path: "/admin/scope-sets",
        icon: "Boxes",
        perm: "scope_sets.manage",
      },
      {
        label: "admin.sidebar.approvals",
        path: "/admin/approvals",
        icon: "CheckSquare",
        perm: "approvals.view",
      },
      {
        label: "admin.sidebar.sharing",
        path: "/admin/sharing",
        icon: "Share2",
        perm: "sharing.read",
      },
      {
        label: "admin.sidebar.chat_compliance",
        path: "/admin/chat-compliance",
        icon: "ShieldCheck",
        perm: "chat.compliance_view",
      },
      // Content-governance surfaces (drive.view) live HERE, not in the
      // System console: Go's ConsoleScopes[system] also DERIVES the
      // requireSystemPerm route guard, so drive.view can never be added
      // there — a drive.view-only admin must see these pages via the
      // Access console (the sharing/chat-compliance precedent).
      {
        label: "admin.sidebar.drive",
        path: "/admin/drive",
        icon: "HardDrive",
        perm: "drive.view",
      },
      {
        label: "admin.sidebar.meet_recordings",
        path: "/admin/meet-recordings",
        icon: "Video",
        perm: "drive.view",
      },
      {
        label: "admin.sidebar.federation",
        path: "/admin/federation",
        icon: "Globe",
        perm: "federation.manage",
      },
    ],
  },
];

/**
 * Return consoles (in declared order) filtered to only those whose id is in
 * the provided list. The list typically comes from the session's
 * `admin.consoles` string array.
 */
export function navForConsoles(ids: ConsoleId[]): ConsoleDef[] {
  return CONSOLES.filter((c) => ids.includes(c.id));
}
