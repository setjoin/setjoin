//! Wire shapes translated from frozen Go; field order, nil slices and omissions are observable.

#[derive(Default)]
pub struct Raw(Option<Box<serde_json::value::RawValue>>);
impl Raw {
    fn is_absent(&self) -> bool {
        self.0.is_none()
    }
}
impl<'de> serde::Deserialize<'de> for Raw {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Some(serde::Deserialize::deserialize(d)?)))
    }
}
impl serde::Serialize for Raw {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(raw) => raw.serialize(s),
            None => s.serialize_none(),
        }
    }
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct ApprovalPolicy {
    #[serde(rename = "id", skip_serializing_if = "zero")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: i64,
    #[serde(rename = "consumerType")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub consumer_type: String,
    #[serde(rename = "name")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub name: String,
    #[serde(rename = "enabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub enabled: bool,
    #[serde(rename = "priority", skip_serializing_if = "zero")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub priority: i64,
    #[serde(rename = "conditions", skip_serializing_if = "Raw::is_absent")]
    pub conditions: Raw,
    #[serde(rename = "requiresApproval")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub requires_approval: bool,
    #[serde(rename = "approverSpec", skip_serializing_if = "Raw::is_absent")]
    pub approver_spec: Raw,
    #[serde(rename = "createdAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "updatedAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub updated_at: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RoleRow {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: i64,
    #[serde(rename = "name")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub name: String,
    #[serde(rename = "description")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub description: String,
    #[serde(rename = "permissions")]
    pub permissions: Option<Vec<String>>,
    #[serde(rename = "domainScope", skip_serializing_if = "Option::is_none")]
    pub domain_scope: Option<i64>,
    #[serde(rename = "isBuiltin")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub is_builtin: bool,
    #[serde(rename = "memberCount")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub member_count: i64,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub updated_at: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RoleMemberRow {
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: i64,
    #[serde(rename = "userEmail")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_email: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RoleExport {
    #[serde(rename = "roles")]
    pub roles: Option<Vec<RoleExportEntry>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct RoleExportEntry {
    #[serde(rename = "name")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub name: String,
    #[serde(rename = "description")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub description: String,
    #[serde(rename = "permissions")]
    pub permissions: Option<Vec<String>>,
    #[serde(rename = "domainScope", skip_serializing_if = "Option::is_none")]
    pub domain_scope: Option<i64>,
    #[serde(rename = "isBuiltin", skip_serializing_if = "zero")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub is_builtin: bool,
    #[serde(rename = "members")]
    pub members: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct OfficeDoctorReport {
    #[serde(rename = "source")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source: String,
    #[serde(rename = "endpoint")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub endpoint: String,
    #[serde(rename = "flags")]
    pub flags: Option<Vec<OfficeFlagStatus>>,
    #[serde(rename = "hints")]
    pub hints: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct OfficeFlagStatus {
    #[serde(rename = "key")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub key: String,
    #[serde(rename = "label")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub label: String,
    #[serde(rename = "present")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub present: bool,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "enabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub enabled: bool,
    #[serde(rename = "defaultEnabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub default_enabled: bool,
    #[serde(rename = "defaultOff")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub default_off: bool,
    #[serde(rename = "configured")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub configured: bool,
    #[serde(rename = "gatewayEffective")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub gateway_effective: bool,
    #[serde(rename = "gatewaySource")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub gateway_source: String,
    #[serde(rename = "registryMode", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub registry_mode: String,
    #[serde(rename = "classification", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub classification: String,
    #[serde(rename = "changeMode", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub change_mode: String,
    #[serde(rename = "disableBehavior", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub disable_behavior: String,
    #[serde(rename = "dependencies")]
    pub dependencies: Option<Vec<String>>,
    #[serde(rename = "confirmationRequired")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub confirmation_required: bool,
    #[serde(rename = "hint", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub hint: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct OfficeDiagnosticsReport {
    #[serde(rename = "source")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source: String,
    #[serde(rename = "endpoint")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub endpoint: String,
    #[serde(rename = "status")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub status: String,
    #[serde(rename = "flags")]
    pub flags: Option<Vec<OfficeDiagnosticFlag>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct OfficeDiagnosticFlag {
    #[serde(rename = "key")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub key: String,
    #[serde(rename = "label")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub label: String,
    #[serde(rename = "present")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub present: bool,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "enabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub enabled: bool,
    #[serde(rename = "defaultEnabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub default_enabled: bool,
    #[serde(rename = "configured")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub configured: bool,
    #[serde(rename = "gatewayEffective")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub gateway_effective: bool,
    #[serde(rename = "gatewaySource")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub gateway_source: String,
    #[serde(rename = "dependencies")]
    pub dependencies: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponse {
    #[serde(rename = "schemaVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub schema_version: i64,
    #[serde(rename = "generatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generated_at: String,
    #[serde(rename = "people")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub people: IdentityInventoryResponsePeople,
    #[serde(rename = "mailboxes")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub mailboxes: IdentityInventoryResponseMailboxes,
    #[serde(rename = "lifecycleSources")]
    pub lifecycle_sources: Option<std::collections::BTreeMap<String, i64>>,
    #[serde(rename = "federationPairs")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub federation_pairs: IdentityInventoryResponseFederationPairs,
    #[serde(rename = "protectedAccounts")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub protected_accounts: IdentityInventoryResponseProtectedAccounts,
    #[serde(rename = "entitlementAmbiguity")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub entitlement_ambiguity: IdentityInventoryResponseEntitlementAmbiguity,
    #[serde(rename = "connectorSecrets")]
    pub connector_secrets: Option<std::collections::BTreeMap<String, String>>,
    #[serde(rename = "blockers")]
    pub blockers: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponsePeople {
    #[serde(rename = "total")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub total: i64,
    #[serde(rename = "enabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub enabled: i64,
    #[serde(rename = "disabled")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub disabled: i64,
    #[serde(rename = "guests")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub guests: i64,
    #[serde(rename = "members")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub members: i64,
    #[serde(rename = "unclassifiedWithoutMailbox")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub unclassified_without_mailbox: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponseMailboxes {
    #[serde(rename = "shared")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub shared: i64,
    #[serde(rename = "resources")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub resources: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponseFederationPairs {
    #[serde(rename = "oidcComplete")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub oidc_complete: i64,
    #[serde(rename = "oidcPartial")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub oidc_partial: i64,
    #[serde(rename = "samlComplete")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub saml_complete: i64,
    #[serde(rename = "samlPartial")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub saml_partial: i64,
    #[serde(rename = "legacyInventoried")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub legacy_inventoried: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponseProtectedAccounts {
    #[serde(rename = "total")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub total: i64,
    #[serde(rename = "breakGlass")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub break_glass: i64,
    #[serde(rename = "sensitiveRoleHolders")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sensitive_role_holders: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryResponseEntitlementAmbiguity {
    #[serde(rename = "distributionGroupMemberships")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub distribution_group_memberships: i64,
    #[serde(rename = "adminRoleAssignments")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub admin_role_assignments: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentitySourceList {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentitySource>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentitySource {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "displayName")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub display_name: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "mappingVersion", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub mapping_version: String,
    #[serde(rename = "capabilities")]
    pub capabilities: Raw,
    #[serde(rename = "lastSuccessAt", skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(rename = "lastFailureAt", skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<String>,
    #[serde(rename = "lastErrorCode", skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
    #[serde(rename = "hasCursor")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub has_cursor: bool,
    #[serde(rename = "attentionCount")]
    pub attention_count: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentitySourceDetail {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "displayName")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub display_name: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "mappingVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub mapping_version: String,
    #[serde(rename = "capabilities")]
    pub capabilities: Raw,
    #[serde(rename = "document")]
    pub document: Raw,
    #[serde(rename = "secretConfigured")]
    pub secret_configured: Option<std::collections::BTreeMap<String, bool>>,
    #[serde(rename = "lastSuccessAt", skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(rename = "lastFailureAt", skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<String>,
    #[serde(rename = "lastErrorCode", skip_serializing_if = "Option::is_none")]
    pub last_error_code: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentitySourcePlanResult {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "create")]
    pub create: Option<bool>,
    #[serde(rename = "changed")]
    pub changed: Option<bool>,
    #[serde(rename = "currentGeneration", skip_serializing_if = "Option::is_none")]
    pub current_generation: Option<String>,
    #[serde(rename = "desired")]
    pub desired: Raw,
    #[serde(rename = "operations")]
    pub operations: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentitySourceMutationResult {
    #[serde(rename = "sourceId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_id: String,
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "replayed")]
    pub replayed: Option<bool>,
    #[serde(rename = "secretName", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub secret_name: String,
    #[serde(rename = "secretConfigured", skip_serializing_if = "Raw::is_absent")]
    pub secret_configured: Raw,
    #[serde(rename = "valid", skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(rename = "transport", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transport: String,
    #[serde(rename = "personWrites", skip_serializing_if = "Option::is_none")]
    pub person_writes: Option<i64>,
    #[serde(rename = "blockers", skip_serializing_if = "option_vec_empty")]
    pub blockers: Option<Vec<String>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPeopleList {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentityPerson>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPerson {
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: String,
    #[serde(rename = "email")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub email: String,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "lifecycleAuthority")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub lifecycle_authority: String,
    #[serde(rename = "sourceKey", skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,
    #[serde(rename = "activeLinks")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub active_links: i64,
    #[serde(rename = "detachedLinks")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub detached_links: i64,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetail {
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: String,
    #[serde(rename = "email")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "relationship")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub relationship: String,
    #[serde(rename = "protected")]
    pub protected: Option<bool>,
    #[serde(rename = "lifecycleAuthority")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub lifecycle_authority: IdentityPersonDetailLifecycleAuthority,
    #[serde(rename = "recovery")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub recovery: IdentityPersonDetailRecovery,
    #[serde(rename = "links")]
    pub links: Option<Vec<IdentityPersonDetailLinks>>,
    #[serde(rename = "fieldAuthority")]
    pub field_authority: Option<Vec<IdentityPersonDetailFieldAuthority>>,
    #[serde(rename = "entitlementProvenance")]
    pub entitlement_provenance: Option<Vec<IdentityPersonDetailEntitlementProvenance>>,
    #[serde(rename = "transitionHistory")]
    pub transition_history: Option<Vec<IdentityPersonDetailTransitionHistory>>,
    #[serde(rename = "linkHistory")]
    pub link_history: Option<Vec<IdentityPersonDetailLinkHistory>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailLifecycleAuthority {
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
    #[serde(rename = "sourceKey")]
    pub source_key: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailRecovery {
    #[serde(rename = "hasLocalPassword")]
    pub has_local_password: Option<bool>,
    #[serde(rename = "passkeyCount")]
    pub passkey_count: Option<i64>,
    #[serde(rename = "activeAuthenticationLinks")]
    pub active_authentication_links: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailLinks {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "sourceKind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_kind: String,
    #[serde(rename = "purposes")]
    pub purposes: Option<Vec<String>>,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "linkMethod")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub link_method: String,
    #[serde(rename = "subjectFingerprint")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub subject_fingerprint: String,
    #[serde(rename = "firstSeenAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub first_seen_at: String,
    #[serde(rename = "lastSeenAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub last_seen_at: String,
    #[serde(rename = "detachedAt")]
    pub detached_at: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailFieldAuthority {
    #[serde(rename = "field")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub field: String,
    #[serde(rename = "authorityKind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub authority_kind: String,
    #[serde(rename = "sourceKey")]
    pub source_key: Option<String>,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "localOverrideState")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub local_override_state: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailEntitlementProvenance {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "targetId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub target_id: String,
    #[serde(rename = "entitlementId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub entitlement_id: String,
    #[serde(rename = "sourceGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_generation: String,
    #[serde(rename = "sourceKey")]
    pub source_key: Option<String>,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
    #[serde(rename = "validUntil")]
    pub valid_until: Option<String>,
    #[serde(rename = "revokedAt")]
    pub revoked_at: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailTransitionHistory {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub updated_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityPersonDetailLinkHistory {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "occurredAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub occurred_at: String,
    #[serde(rename = "reason")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub reason: String,
    #[serde(rename = "correlationId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub correlation_id: String,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictList {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentityConflict>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflict {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "evidenceClass")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub evidence_class: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "createdAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "expiresAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
    #[serde(rename = "explanation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub explanation: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictDetail {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "source")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source: IdentityConflictDetailSource,
    #[serde(rename = "subjectFingerprint")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub subject_fingerprint: String,
    #[serde(rename = "evidenceClass")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub evidence_class: String,
    #[serde(rename = "evidenceDigest")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub evidence_digest: String,
    #[serde(rename = "explanation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub explanation: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
    #[serde(rename = "decidedAt")]
    pub decided_at: Option<String>,
    #[serde(rename = "candidatePerson")]
    pub candidate_person: Option<IdentityConflictDetailCandidatePerson>,
    #[serde(rename = "allowedDecisions")]
    pub allowed_decisions: Option<Vec<String>>,
    #[serde(rename = "decisionHistory")]
    pub decision_history: Option<Vec<IdentityConflictDetailDecisionHistory>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictDetailSource {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "displayName")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub display_name: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictDetailCandidatePerson {
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: String,
    #[serde(rename = "email")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "protected")]
    pub protected: Option<bool>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictDetailDecisionHistory {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "decision")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub decision: String,
    #[serde(rename = "reason")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub reason: String,
    #[serde(rename = "personId")]
    pub person_id: Option<String>,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
    #[serde(rename = "decidedBy")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub decided_by: String,
    #[serde(rename = "occurredAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub occurred_at: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityConflictDecisionResult {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "personId")]
    pub person_id: Option<String>,
    #[serde(rename = "linkId")]
    pub link_id: Option<String>,
    #[serde(rename = "replayed")]
    pub replayed: Option<bool>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionList {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentityTransition>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransition {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "protected")]
    pub protected: Option<bool>,
    #[serde(rename = "reason", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub reason: String,
    #[serde(rename = "failureCode", skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(rename = "createdAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "updatedAt", skip_serializing_if = "String::is_empty")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub updated_at: String,
    #[serde(rename = "pendingEffects")]
    pub pending_effects: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityEventList {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentityEvent>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityEvent {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "occurredAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub occurred_at: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "sourceKey", skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,
    #[serde(rename = "linkId", skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    #[serde(rename = "transitionId", skip_serializing_if = "Option::is_none")]
    pub transition_id: Option<String>,
    #[serde(rename = "action")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub action: String,
    #[serde(rename = "reason")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub reason: String,
    #[serde(rename = "correlationId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub correlation_id: String,
    #[serde(rename = "metadata", skip_serializing_if = "Raw::is_absent")]
    pub metadata: Raw,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionPreview {
    #[serde(rename = "transitionId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_id: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "transitionGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_generation: String,
    #[serde(rename = "previewVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_version: String,
    #[serde(rename = "previewDigest")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_digest: String,
    #[serde(rename = "previewExpiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_expires_at: String,
    #[serde(rename = "protected")]
    pub protected: Option<bool>,
    #[serde(rename = "recoveryReady")]
    pub recovery_ready: Option<bool>,
    #[serde(rename = "sourceGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_generation: String,
    #[serde(rename = "linkGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub link_generation: String,
    #[serde(rename = "lifecycleGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub lifecycle_generation: String,
    #[serde(rename = "replayed", skip_serializing_if = "zero")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub replayed: bool,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionDetail {
    #[serde(rename = "transitionId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_id: String,
    #[serde(rename = "correlationId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub correlation_id: String,
    #[serde(rename = "personId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub person_id: String,
    #[serde(rename = "type")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub r#type: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "transitionGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_generation: String,
    #[serde(rename = "previewVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_version: String,
    #[serde(rename = "previewDigest")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_digest: String,
    #[serde(rename = "previewExpiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_expires_at: String,
    #[serde(rename = "protected")]
    pub protected: Option<bool>,
    #[serde(rename = "approvalRequestId")]
    pub approval_request_id: Option<String>,
    #[serde(rename = "failureCode")]
    pub failure_code: Option<String>,
    #[serde(rename = "rollback")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub rollback: IdentityTransitionDetailRollback,
    #[serde(rename = "steps")]
    pub steps: Option<Vec<Raw>>,
    #[serde(rename = "effects")]
    pub effects: Option<Vec<IdentityTransitionEffect>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionDetailRollback {
    #[serde(rename = "boundary")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub boundary: String,
    #[serde(rename = "previewDigest")]
    pub preview_digest: Option<String>,
    #[serde(rename = "previewExpiresAt")]
    pub preview_expires_at: Option<String>,
    #[serde(rename = "approvalRequestId")]
    pub approval_request_id: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionEffect {
    #[serde(rename = "effectId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub effect_id: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "attemptCount")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub attempt_count: i64,
    #[serde(rename = "nextAttemptAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_attempt_at: String,
    #[serde(rename = "lastErrorCode")]
    pub last_error_code: Option<String>,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionChallenge {
    #[serde(rename = "challengeId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub challenge_id: String,
    #[serde(rename = "transitionId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_id: String,
    #[serde(rename = "transitionGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_generation: String,
    #[serde(rename = "previewDigest")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub preview_digest: String,
    #[serde(rename = "expiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
    #[serde(rename = "handoffMethod")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub handoff_method: String,
    #[serde(rename = "displayCode")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub display_code: String,
    #[serde(rename = "completed")]
    pub completed: Option<bool>,
    #[serde(rename = "invalidated")]
    pub invalidated: Option<bool>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionElevation {
    #[serde(rename = "challengeId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub challenge_id: String,
    #[serde(rename = "elevationId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub elevation_id: String,
    #[serde(rename = "transitionId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_id: String,
    #[serde(rename = "transitionGeneration")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub transition_generation: String,
    #[serde(rename = "expiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
    #[serde(rename = "consumed")]
    pub consumed: Option<bool>,
    #[serde(rename = "invalidated")]
    pub invalidated: Option<bool>,
    #[serde(rename = "replayed")]
    pub replayed: Option<bool>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeStatus {
    #[serde(rename = "schemaVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub schema_version: i64,
    #[serde(rename = "masterEnabled")]
    pub master_enabled: Option<bool>,
    #[serde(rename = "normalizedReadsEnabled")]
    pub normalized_reads_enabled: Option<bool>,
    #[serde(rename = "transitionsEnabled")]
    pub transitions_enabled: Option<bool>,
    #[serde(rename = "sources")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sources: IdentityUpgradeStatusSources,
    #[serde(rename = "blockers")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub blockers: IdentityUpgradeStatusBlockers,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeStatusSources {
    #[serde(rename = "total")]
    pub total: Option<i64>,
    #[serde(rename = "shadow")]
    pub shadow: Option<i64>,
    #[serde(rename = "canary")]
    pub canary: Option<i64>,
    #[serde(rename = "normalized")]
    pub normalized: Option<i64>,
    #[serde(rename = "cohortMembers")]
    pub cohort_members: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeStatusBlockers {
    #[serde(rename = "criticalDivergences")]
    pub critical_divergences: Option<i64>,
    #[serde(rename = "pendingCandidates")]
    pub pending_candidates: Option<i64>,
    #[serde(rename = "pendingEffects")]
    pub pending_effects: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeCanaryResult {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "readMode")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub read_mode: String,
    #[serde(rename = "cohortSize")]
    pub cohort_size: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeRollbackResult {
    #[serde(rename = "rolledBack")]
    pub rolled_back: Option<bool>,
    #[serde(rename = "pendingEffects")]
    pub pending_effects: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityDoctor {
    #[serde(rename = "generatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generated_at: String,
    #[serde(rename = "sourceKey")]
    pub source_key: Option<String>,
    #[serde(rename = "passed")]
    pub passed: Option<bool>,
    #[serde(rename = "blockingCount")]
    pub blocking_count: Option<i64>,
    #[serde(rename = "checks")]
    pub checks: Option<Vec<IdentityDoctorCheck>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityDoctorCheck {
    #[serde(rename = "name")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub name: String,
    #[serde(rename = "severity")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub severity: String,
    #[serde(rename = "passed")]
    pub passed: Option<bool>,
    #[serde(rename = "facts")]
    pub facts: Raw,
    #[serde(rename = "nextAction")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_action: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryExport {
    #[serde(rename = "manifestVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub manifest_version: String,
    #[serde(rename = "schemaVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub schema_version: i64,
    #[serde(rename = "generatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generated_at: String,
    #[serde(rename = "redactionPolicy")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub redaction_policy: String,
    #[serde(rename = "sha256")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sha256: String,
    #[serde(rename = "sources")]
    pub sources: Option<Vec<IdentityInventorySource>>,
    #[serde(rename = "people")]
    pub people: Option<Vec<IdentityInventoryPerson>>,
    #[serde(rename = "conflicts")]
    pub conflicts: Option<Vec<IdentityInventoryConflict>>,
    #[serde(rename = "redactionCounts")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub redaction_counts: IdentityInventoryExportRedactionCounts,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventorySource {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "readMode")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub read_mode: String,
    #[serde(rename = "activeLinks")]
    pub active_links: Option<i64>,
    #[serde(rename = "openConflicts")]
    pub open_conflicts: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryPerson {
    #[serde(rename = "userId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub user_id: String,
    #[serde(rename = "enabled")]
    pub enabled: Option<bool>,
    #[serde(rename = "accountClass")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub account_class: String,
    #[serde(rename = "lifecycleAuthority")]
    pub lifecycle_authority: Option<String>,
    #[serde(rename = "activeLinks")]
    pub active_links: Option<i64>,
    #[serde(rename = "detachedLinks")]
    pub detached_links: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryConflict {
    #[serde(rename = "id")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub id: String,
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "evidenceClass")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub evidence_class: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "generation")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generation: String,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityInventoryExportRedactionCounts {
    #[serde(rename = "emailsOmitted")]
    pub emails_omitted: Option<i64>,
    #[serde(rename = "externalSubjectsOmitted")]
    pub external_subjects_omitted: Option<i64>,
    #[serde(rename = "candidateSubjectsOmitted")]
    pub candidate_subjects_omitted: Option<i64>,
    #[serde(rename = "secretsOmitted")]
    pub secrets_omitted: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityJob {
    #[serde(rename = "jobId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub job_id: String,
    #[serde(rename = "kind")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub kind: String,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "snapshotId")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub snapshot_id: String,
    #[serde(rename = "sourceKey")]
    pub source_key: Option<String>,
    #[serde(rename = "transitionId")]
    pub transition_id: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub expires_at: String,
    #[serde(rename = "progress")]
    pub progress: Raw,
    #[serde(rename = "nextAction")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_action: String,
    #[serde(rename = "terminal")]
    pub terminal: Option<bool>,
    #[serde(rename = "cancelRequested")]
    pub cancel_requested: Option<bool>,
    #[serde(rename = "manifestVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub manifest_version: String,
    #[serde(rename = "byteCount")]
    pub byte_count: Option<i64>,
    #[serde(rename = "sha256")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sha256: String,
    #[serde(rename = "redactionCounts")]
    pub redaction_counts: Option<std::collections::BTreeMap<String, i64>>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityJobResults {
    #[serde(rename = "items")]
    pub items: Option<Vec<IdentityJobResult>>,
    #[serde(rename = "nextSequence")]
    pub next_sequence: Option<String>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityJobResult {
    #[serde(rename = "sequence")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sequence: String,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "state")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub state: String,
    #[serde(rename = "result")]
    pub result: Raw,
    #[serde(rename = "createdAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub created_at: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradePreflight {
    #[serde(rename = "manifestVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub manifest_version: String,
    #[serde(rename = "generatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generated_at: String,
    #[serde(rename = "phase")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub phase: String,
    #[serde(rename = "checks")]
    pub checks: Option<Vec<IdentityDoctorCheck>>,
    #[serde(rename = "blockers")]
    pub blockers: Option<Vec<String>>,
    #[serde(rename = "safeToBackfill")]
    pub safe_to_backfill: Option<bool>,
    #[serde(rename = "featureFlags")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub feature_flags: IdentityUpgradePreflightFeatureFlags,
    #[serde(rename = "estimates")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub estimates: IdentityUpgradePreflightEstimates,
    #[serde(rename = "sha256")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub sha256: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradePreflightFeatureFlags {
    #[serde(rename = "identityModelV2")]
    pub identity_model_v2: Option<bool>,
    #[serde(rename = "normalizedReads")]
    pub normalized_reads: Option<bool>,
    #[serde(rename = "transitions")]
    pub transitions: Option<bool>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradePreflightEstimates {
    #[serde(rename = "people")]
    pub people: Option<i64>,
    #[serde(rename = "maximumBatchSize")]
    pub maximum_batch_size: Option<i64>,
    #[serde(rename = "maximumDurationSeconds")]
    pub maximum_duration_seconds: Option<i64>,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeShadow {
    #[serde(rename = "sourceKey")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub source_key: String,
    #[serde(rename = "eligible")]
    pub eligible: Option<bool>,
    #[serde(rename = "completedSyncs")]
    pub completed_syncs: Option<i64>,
    #[serde(rename = "requiredSyncs")]
    pub required_syncs: Option<i64>,
    #[serde(rename = "windowStartedAt")]
    pub window_started_at: Option<String>,
    #[serde(rename = "windowHours", serialize_with = "optional_float")]
    pub window_hours: Option<f64>,
    #[serde(rename = "requiredWindowHours")]
    pub required_window_hours: Option<i64>,
    #[serde(rename = "criticalDivergences")]
    pub critical_divergences: Option<i64>,
    #[serde(rename = "missingProjections")]
    pub missing_projections: Option<i64>,
    #[serde(rename = "undispositionedAmbiguities")]
    pub undispositioned_ambiguities: Option<i64>,
    #[serde(rename = "nextAction")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_action: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityUpgradeRetirementCheck {
    #[serde(rename = "ready")]
    pub ready: Option<bool>,
    #[serde(rename = "destructiveMigrationIncluded")]
    pub destructive_migration_included: Option<bool>,
    #[serde(rename = "checks")]
    pub checks: Option<Vec<IdentityRetirementCheck>>,
    #[serde(rename = "nextAction")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_action: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityRetirementCheck {
    #[serde(rename = "name")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub name: String,
    #[serde(rename = "passed")]
    pub passed: Option<bool>,
    #[serde(rename = "nextAction")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub next_action: String,
}
#[derive(Default, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct IdentityTransitionReport {
    #[serde(rename = "schemaVersion")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub schema_version: i64,
    #[serde(rename = "generatedAt")]
    #[serde(deserialize_with = "crate::models::null_default")]
    pub generated_at: String,
    #[serde(rename = "transition")]
    pub transition: Raw,
    #[serde(rename = "effects")]
    pub effects: Option<Vec<Raw>>,
    #[serde(rename = "events")]
    pub events: Option<Vec<Raw>>,
}

fn zero<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}
pub fn json(name: &str, raw: &str) -> Result<String, crate::client::Failure> {
    match name {
        "approvalPolicy" => {
            let v: Option<ApprovalPolicy> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "[]approvalPolicy" => {
            let v: Option<Vec<ApprovalPolicy>> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "roleRow" => {
            let v: Option<RoleRow> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "[]roleRow" => {
            let v: Option<Vec<RoleRow>> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "roleMemberRow" => {
            let v: Option<RoleMemberRow> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "[]roleMemberRow" => {
            let v: Option<Vec<RoleMemberRow>> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "roleExport" => {
            let v: Option<RoleExport> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "officeDoctorReport" => {
            let v: Option<OfficeDoctorReport> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "officeDiagnosticsReport" => {
            let v: Option<OfficeDiagnosticsReport> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityInventoryResponse" => {
            let v: Option<IdentityInventoryResponse> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identitySourceList" => {
            let v: Option<IdentitySourceList> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identitySourceDetail" => {
            let v: Option<IdentitySourceDetail> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identitySourcePlanResult" => {
            let v: Option<IdentitySourcePlanResult> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identitySourceMutationResult" => {
            let v: Option<IdentitySourceMutationResult> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityPeopleList" => {
            let v: Option<IdentityPeopleList> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityPersonDetail" => {
            let v: Option<IdentityPersonDetail> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityConflictList" => {
            let v: Option<IdentityConflictList> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityConflictDetail" => {
            let v: Option<IdentityConflictDetail> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityConflictDecisionResult" => {
            let v: Option<IdentityConflictDecisionResult> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionList" => {
            let v: Option<IdentityTransitionList> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityEventList" => {
            let v: Option<IdentityEventList> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionPreview" => {
            let v: Option<IdentityTransitionPreview> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionDetail" => {
            let v: Option<IdentityTransitionDetail> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionChallenge" => {
            let v: Option<IdentityTransitionChallenge> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionElevation" => {
            let v: Option<IdentityTransitionElevation> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradeStatus" => {
            let v: Option<IdentityUpgradeStatus> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradeCanaryResult" => {
            let v: Option<IdentityUpgradeCanaryResult> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradeRollbackResult" => {
            let v: Option<IdentityUpgradeRollbackResult> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityDoctor" => {
            let v: Option<IdentityDoctor> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityInventoryExport" => {
            let v: Option<IdentityInventoryExport> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityJob" => {
            let v: Option<IdentityJob> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityJobResults" => {
            let v: Option<IdentityJobResults> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradePreflight" => {
            let v: Option<IdentityUpgradePreflight> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradeShadow" => {
            let v: Option<IdentityUpgradeShadow> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityUpgradeRetirementCheck" => {
            let v: Option<IdentityUpgradeRetirementCheck> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        "identityTransitionReport" => {
            let v: Option<IdentityTransitionReport> =
                serde_json::from_str(raw).map_err(|e| crate::client::json_error(raw, &e, false))?;
            let v = v.unwrap_or_default();
            Ok(crate::part_b::ordered_pretty(
                &serde_json::to_string(&v).unwrap(),
            ))
        }
        _ => unreachable!("unknown wire shape {name}"),
    }
}

fn optional_float<S: serde::Serializer>(v: &Option<f64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => crate::models::float(v, s),
        None => s.serialize_none(),
    }
}

fn option_vec_empty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_none_or(Vec::is_empty)
}
