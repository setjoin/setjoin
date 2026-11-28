param(
    [switch]$SyntaxOnly
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$files = Get-ChildItem -Path (Join-Path $root 'scripts') -Filter '*.ps1' -Recurse -File
$syntaxErrors = foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$errors
    )
    $errors
}
if ($syntaxErrors) {
    $syntaxErrors | Format-Table -AutoSize | Out-String | Write-Error
    exit 1
}

Write-Output 'PowerShell syntax: clean'
if ($SyntaxOnly) {
    exit 0
}

if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
    throw 'PSScriptAnalyzer is required on the Windows CI quality lane'
}

$findings = foreach ($file in $files) {
    Invoke-ScriptAnalyzer -Path $file.FullName -Severity Error, Warning
}
if ($findings) {
    $findings | Format-Table -AutoSize | Out-String | Write-Error
    exit 1
}

Write-Output 'PSScriptAnalyzer: clean'
