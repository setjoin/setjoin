#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RegistryPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 256)]
    [string]$OrganizationLabel,

    [ValidateSet('on-premises', 'hybrid')]
    [string]$Topology = 'on-premises',

    [ValidateRange(1, 100000)]
    [int]$MaxMailboxes = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A0 is deliberately a fixed, read-only concierge collector. Never replace this
# switch with Invoke-Expression, ScriptBlock creation, or command names supplied by
# a registry/customer file. The registry may describe only this compiled allowlist.
$compiledAllowlist = @(
    'Get-ExchangeServer',
    'Get-OrganizationConfig',
    'Get-Mailbox',
    'Get-MailboxPermission',
    'Get-RecipientPermission',
    'Get-MailboxFolderStatistics',
    'Get-MailboxFolderPermission',
    'Get-CalendarProcessing',
    'Get-DistributionGroup',
    'Get-DistributionGroupMember'
)

function Format-ProbeResult {
    param(
        [string]$CapabilityId,
        [string]$Status,
        [object]$Facts,
        [string]$DiagnosticId = '',
        [string]$Detail = ''
    )
    [ordered]@{
        capabilityId = $CapabilityId
        status = $Status
        diagnosticId = $DiagnosticId
        detail = $Detail
        facts = $Facts
    }
}

function Get-ExceptionSummary {
    param([System.Management.Automation.ErrorRecord]$Record)
    # Exception prose can contain mailbox identities or server names. Retain only
    # bounded type/category identifiers in the portable report. Full exception
    # prose stays outside the portable artifact and can be inspected separately.
    $summary = "$($Record.CategoryInfo.Category);$($Record.Exception.GetType().FullName);$($Record.FullyQualifiedErrorId)" -replace '[\r\n\t]+', ' '
    if ($summary.Length -gt 500) { $summary = $summary.Substring(0, 500) }
    $summary
}

if (-not (Test-Path -LiteralPath $RegistryPath -PathType Leaf)) {
    throw "Registry is not a regular file: $RegistryPath"
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to replace existing output: $OutputPath"
}

$registryBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $RegistryPath))
$registry = [System.Text.Encoding]::UTF8.GetString($registryBytes) | ConvertFrom-Json
if ($registry.schemaVersion -ne 'setjoin.exchange.a0.registry/v0') {
    throw "Unsupported registry schema: $($registry.schemaVersion)"
}
$registryCommands = @($registry.capabilities | ForEach-Object { $_.commands } | Sort-Object -Unique)
$unexpectedCommands = @($registryCommands | Where-Object { $_ -notin $compiledAllowlist })
if ($unexpectedCommands.Count -ne 0) {
    throw "Registry requests commands outside the compiled read-only allowlist: $($unexpectedCommands -join ', ')"
}
$missingDescriptions = @($compiledAllowlist | Where-Object { $_ -notin $registryCommands })
if ($missingDescriptions.Count -ne 0) {
    throw "Registry omits compiled commands: $($missingDescriptions -join ', ')"
}
$registryDigest = (Get-FileHash -LiteralPath $RegistryPath -Algorithm SHA256).Hash.ToLowerInvariant()

$unavailable = @($compiledAllowlist | Where-Object { -not (Get-Command -Name $_ -ErrorAction SilentlyContinue) })
if ($unavailable.Count -ne 0) {
    throw "Exchange Management Shell is missing required read-only commands: $($unavailable -join ', ')"
}

$probes = [System.Collections.Generic.List[object]]::new()
$servers = @()
$mailboxes = @()

try {
    $servers = @(Get-ExchangeServer | Sort-Object Name)
    $organization = Get-OrganizationConfig
    $serverFacts = @($servers | Group-Object { "$($_.ServerRole)|$($_.Edition)|$($_.AdminDisplayVersion)" } | ForEach-Object {
        [ordered]@{ signature = $_.Name; count = $_.Count }
    })
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-TOPOLOGY' -Status 'observed' -Facts ([ordered]@{
        serverCount = $servers.Count
        serverSignatures = $serverFacts
        organizationConfigReadable = ($null -ne $organization)
    })))
} catch {
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-TOPOLOGY' -Status 'blocked' -DiagnosticId 'A0-COLLECT-TOPOLOGY' -Detail (Get-ExceptionSummary $_) -Facts ([ordered]@{})))
}

try {
    $mailboxes = @(Get-Mailbox -ResultSize Unlimited | Sort-Object ExchangeGuid)
    if ($mailboxes.Count -gt $MaxMailboxes) {
        throw "Mailbox count $($mailboxes.Count) exceeds approved MaxMailboxes $MaxMailboxes"
    }
    $fullAccess = 0
    $sendAs = 0
    foreach ($mailbox in $mailboxes) {
        $fullAccess += @(
            Get-MailboxPermission -Identity $mailbox.Identity |
                Where-Object { -not $_.IsInherited -and $_.Deny -eq $false -and $_.User -notlike 'NT AUTHORITY\\*' }
        ).Count
        $sendAs += @(
            Get-RecipientPermission -Identity $mailbox.Identity |
                Where-Object { $_.Deny -eq $false -and $_.Trustee -notlike 'NT AUTHORITY\\*' }
        ).Count
    }
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-MAILBOX-DELEGATION' -Status 'observed' -Facts ([ordered]@{
        mailboxCount = $mailboxes.Count
        explicitFullAccessGrantCount = $fullAccess
        explicitSendAsGrantCount = $sendAs
    })))
} catch {
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-MAILBOX-DELEGATION' -Status 'blocked' -DiagnosticId 'A0-COLLECT-DELEGATION' -Detail (Get-ExceptionSummary $_) -Facts ([ordered]@{})))
}

if ($mailboxes.Count -eq 0) {
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-CALENDAR-VISIBILITY' -Status 'unassessed' -DiagnosticId 'A0-MISSING-MAILBOXES' -Detail 'Mailbox inventory was unavailable, so calendar permissions were not assessed.' -Facts ([ordered]@{})))
    $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-RESOURCE-BOOKING' -Status 'unassessed' -DiagnosticId 'A0-MISSING-MAILBOXES' -Detail 'Mailbox inventory was unavailable, so resource policy was not assessed.' -Facts ([ordered]@{})))
} else {
    try {
        $calendarFolders = 0
        $calendarPermissionEntries = 0
        $defaultPermissionLevels = @{}
        foreach ($mailbox in $mailboxes) {
            $folders = @(Get-MailboxFolderStatistics -Identity $mailbox.Identity -FolderScope Calendar | Where-Object { $_.FolderType -eq 'Calendar' })
            foreach ($folder in $folders) {
                $calendarFolders++
                $folderPath = $folder.FolderPath.Replace('/', '\\')
                $identity = "$($mailbox.PrimarySmtpAddress):$folderPath"
                $permissions = @(Get-MailboxFolderPermission -Identity $identity)
                $calendarPermissionEntries += $permissions.Count
                foreach ($permission in $permissions | Where-Object { $_.User.DisplayName -eq 'Default' }) {
                    $level = [string]($permission.AccessRights -join ',')
                    if (-not $defaultPermissionLevels.ContainsKey($level)) { $defaultPermissionLevels[$level] = 0 }
                    $defaultPermissionLevels[$level]++
                }
            }
        }
        $levelFacts = @($defaultPermissionLevels.GetEnumerator() | Sort-Object Name | ForEach-Object { [ordered]@{ level = $_.Name; count = $_.Value } })
        $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-CALENDAR-VISIBILITY' -Status 'observed' -Facts ([ordered]@{
            calendarFolderCount = $calendarFolders
            permissionEntryCount = $calendarPermissionEntries
            defaultAccessDistribution = $levelFacts
        })))
    } catch {
        $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-CALENDAR-VISIBILITY' -Status 'blocked' -DiagnosticId 'A0-COLLECT-CALENDAR' -Detail (Get-ExceptionSummary $_) -Facts ([ordered]@{})))
    }

    try {
        $resources = @($mailboxes | Where-Object { $_.RecipientTypeDetails -in @('RoomMailbox', 'EquipmentMailbox') })
        $policies = @($resources | ForEach-Object { Get-CalendarProcessing -Identity $_.Identity })
        $roomLists = @(Get-DistributionGroup -ResultSize Unlimited -RecipientTypeDetails RoomList)
        $roomListMemberships = 0
        foreach ($roomList in $roomLists) {
            $roomListMemberships += @(Get-DistributionGroupMember -Identity $roomList.Identity -ResultSize Unlimited).Count
        }
        $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-RESOURCE-BOOKING' -Status 'observed' -Facts ([ordered]@{
            resourceMailboxCount = $resources.Count
            autoAcceptCount = @($policies | Where-Object { $_.AutomateProcessing -eq 'AutoAccept' }).Count
            approvalRequiredCount = @($policies | Where-Object { $_.AllBookInPolicy -eq $false -or $_.AllRequestInPolicy -eq $true -or $_.AllRequestOutOfPolicy -eq $true }).Count
            conflictAllowedCount = @($policies | Where-Object { $_.AllowConflicts -eq $true }).Count
            roomListCount = $roomLists.Count
            roomListMembershipCount = $roomListMemberships
        })))
    } catch {
        $probes.Add((Format-ProbeResult -CapabilityId 'EX-A0-RESOURCE-BOOKING' -Status 'blocked' -DiagnosticId 'A0-COLLECT-RESOURCE' -Detail (Get-ExceptionSummary $_) -Facts ([ordered]@{})))
    }
}

$builds = @($servers | ForEach-Object { [string]$_.AdminDisplayVersion } | Sort-Object -Unique)
if ($builds.Count -eq 0) { $builds = @('unknown') }
$artifact = [ordered]@{
    schemaVersion = 'setjoin.exchange.a0.input/v0'
    artifactKind = 'assessment-input'
    collectorVersion = 'a0-v0'
    registryDigest = $registryDigest
    collectedAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    source = [ordered]@{
        organization = $OrganizationLabel
        topology = $Topology
        builds = $builds
    }
    probes = @($probes)
}

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$json = $artifact | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, $utf8NoBom)
Write-Output "A0/v0 read-only collector output written to $OutputPath"
Write-Output "This artifact is local concierge evidence and cannot be imported as a product assessment."
