#requires -Version 5.1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Output,
  [string]$SupportCellId = 'EX2019-ONPREM-INITIAL'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (Test-Path -LiteralPath $Output) { throw "Output already exists: $Output" }
$script:Results = New-Object System.Collections.Generic.List[object]
function Invoke-AssessmentProbe {
  param([string]$CapabilityId,[scriptblock]$ReadOnlyProbe)
  try {
    $count = & $ReadOnlyProbe
    $script:Results.Add([ordered]@{ capabilityId=$CapabilityId; state='complete'; diagnosticId='COLLECT-OK'; safeFacts=[ordered]@{ count=[int64]$count } })
  } catch {
    $script:Results.Add([ordered]@{ capabilityId=$CapabilityId; state='failed'; diagnosticId='COLLECT-FAILED'; safeFacts=[ordered]@{ count=0 } })
  }
}

# Fixed, reviewed, read-only command allowlist. No customer identity, message
# content, credential, token, document, or raw exception text is emitted.
Invoke-AssessmentProbe 'EX-ACCEPTED-REMOTE-DOMAINS' { @(Get-AcceptedDomain -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-ADDRESS-LISTS-OAB' { @(Get-AddressList -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-ANTISPAM-MALWARE' { @(Get-ContentFilterConfig -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-ARCHIVE-MAILBOX' { @(Get-Mailbox -Archive -ResultSize Unlimited -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-AUTH-CLIENT-PROTOCOLS' { @(Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-AUTO-REPLIES' { @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Get-MailboxAutoReplyConfiguration -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-CALENDAR-VISIBILITY' { @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Get-MailboxFolderPermission -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-CERTIFICATES-TLS' { @(Get-ExchangeCertificate -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-DATABASE-HA' { @(Get-DatabaseAvailabilityGroup -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-DISTRIBUTION-GROUPS' { @(Get-DynamicDistributionGroup -ResultSize Unlimited -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-DLP' { @(Get-DlpPolicy -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-EDISCOVERY-SEARCH' { @(Get-ComplianceSearch -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-EMAIL-ADDRESS-POLICIES' { @(Get-EmailAddressPolicy -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-FEDERATION-ORG-RELATIONSHIPS' { @(Get-OrganizationRelationship -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-HYBRID-COEXISTENCE' { @(Get-HybridConfiguration -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-INBOX-RULES' { @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Get-InboxRule -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-JOURNALING' { @(Get-JournalRule -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MAIL-FLOW-RULES' { @(Get-TransportRule -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MAILBOX-AUDIT' { @(Get-AdminAuditLogConfig -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MAILBOX-DELEGATION' { @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Get-MailboxPermission -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MIGRATION-SIZING' { @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Get-MailboxStatistics -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MOBILE-ACTIVESYNC' { @(Get-ActiveSyncMailboxPolicy -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-MONITORING-OPERATIONS' { @(Get-Queue -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-PUBLIC-FOLDERS' { @(Get-PublicFolder -Recurse -ResultSize Unlimited -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-QUOTAS-LIMITS' { @(Get-TransportConfig -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-RBAC-MANAGEMENT-SCOPES' { @(Get-RoleGroup -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-RESOURCE-BOOKING' { @(Get-Mailbox -RecipientTypeDetails RoomMailbox,EquipmentMailbox -ResultSize Unlimited -ErrorAction Stop | Get-CalendarProcessing -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-RETENTION-HOLD' { @(Get-RetentionPolicy -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-ROOM-LISTS' { @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop | Get-DistributionGroupMember -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-SEND-RECEIVE-CONNECTORS' { @(Get-SendConnector -ErrorAction Stop).Count }
Invoke-AssessmentProbe 'EX-SHARED-MAILBOX' { @(Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop).Count }

$document = [ordered]@{
  schemaVersion = 'setjoin.exchange.collector-output/v1'
  supportCellId = $SupportCellId
  collectedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
  probes = $script:Results
}
$json = $document | ConvertTo-Json -Depth 8
New-Item -ItemType File -LiteralPath $Output -ErrorAction Stop | Out-Null
[System.IO.File]::WriteAllText((Resolve-Path -LiteralPath $Output), $json + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Collector output written: $Output"
Write-Output "Next: mailctl exchange assess collect --input `"$Output`" --output assessment-output"
