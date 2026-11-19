[CmdletBinding()]
param([string]$ProjectRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FsPath([string]$Path) {
    if ([IO.Path]::DirectorySeparatorChar -eq '\' -and -not $Path.StartsWith('\\?\')) {
        if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
        return '\\?\' + $Path
    }
    return $Path
}
function Get-DisplayPath([string]$Path) {
    if ($Path.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { return '\\' + $Path.Substring(8) }
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}
function Get-ParentPath([string]$Path) {
    # Prefix before .NET path parsing: Windows PowerShell 5.1 may otherwise
    # reject a long path even when the later file operation uses an extended path.
    return Get-DisplayPath ([IO.Path]::GetDirectoryName((Get-FsPath $Path)))
}
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead((Get-FsPath $Path))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}
function Assert-Hash([string]$Hash) {
    if ($Hash -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid SHA-256 value in update manifest.' }
}
function Get-ProjectFile([string]$Relative) {
    if ([string]::IsNullOrEmpty($Relative) -or [IO.Path]::IsPathRooted($Relative) -or
        $Relative.Contains('\') -or $Relative.Split('/').Contains('..')) {
        throw 'Unsafe relative path in update manifest.'
    }
    $combined = [IO.Path]::Combine($script:Root, $Relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
    $result = Get-DisplayPath ([IO.Path]::GetFullPath((Get-FsPath $combined)))
    if (-not $result.StartsWith($script:RootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Update path is outside the project.'
    }
    $node = $result
    while ($node.Length -ge $script:Root.Length) {
        $fs = Get-FsPath $node
        if ([IO.File]::Exists($fs) -or [IO.Directory]::Exists($fs)) {
            if (([IO.File]::GetAttributes($fs) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('Symbolic links or junctions are not supported: ' + $node)
            }
        }
        if ($node -eq $script:Root) { break }
        $node = Get-ParentPath $node
    }
    return $result
}

try {
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Read-Host 'EUNORA project folder (contains gradlew and app)'
    }
    $ProjectRoot = $ProjectRoot.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { throw 'No project folder was provided.' }
    $script:Root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $script:RootPrefix = $script:Root + [IO.Path]::DirectorySeparatorChar
    foreach ($required in @('gradlew', 'app/src/main/java/com/example/wheelprobe/ModuleMain.kt')) {
        if (-not [IO.File]::Exists((Get-FsPath (Get-ProjectFile $required)))) {
            throw ('Not an EUNORA project folder. Missing: ' + $required)
        }
    }
    $manifestPath = Join-Path $PSScriptRoot 'update-manifest.json'
    $manifest = [IO.File]::ReadAllText((Get-FsPath $manifestPath)) | ConvertFrom-Json
    $codeRoot = 'app/src/main/java/com/example/wheelprobe/'
    $expectedReplacements = @('E02.kt', 'E03.kt', 'E04.kt', 'E05.kt', 'E06.kt')
    $expectedDeletions = @(
        ($codeRoot + 'AutoClickService.kt'),
        ($codeRoot + 'ExecutionClient.kt'),
        'app/src/main/res/xml/eunora_accessibility_service.xml',
        ($codeRoot + 'package com/example/wheelprobe  import android/content/BroadcastReceiver import android/content/Context import android/content/Intent import android/util/ErrorReporter.kt')
    )
    if (@($manifest.replacements).Count -ne 5 -or @($manifest.deletions).Count -ne 4) {
        throw 'Unexpected update manifest entries.'
    }
    $seen = @{}
    $replacePlan = @()
    $deletePlan = @()
    foreach ($item in $manifest.replacements) {
        if ($item.source -cnotin $expectedReplacements -or $item.path -cne ($codeRoot + $item.source) -or $seen.ContainsKey($item.path)) {
            throw 'Update manifest contains an unexpected or duplicate replacement.'
        }
        $seen[$item.path] = $true
        Assert-Hash $item.sha256
        foreach ($hash in @($item.allowed_sha256)) { Assert-Hash $hash }
        $source = Join-Path $PSScriptRoot $item.source
        if (-not [IO.File]::Exists((Get-FsPath $source)) -or (Get-Sha256 $source) -cne $item.sha256) {
            throw ('Missing or modified update source: ' + $item.source)
        }
        $destination = Get-ProjectFile $item.path
        if (-not [IO.File]::Exists((Get-FsPath $destination))) { throw ('Missing project source: ' + $item.path) }
        $currentHash = Get-Sha256 $destination
        if ($currentHash -ceq $item.sha256) { continue }
        if ($currentHash -cnotin @($item.allowed_sha256)) {
            throw ('Your source differs from the supported versions. Nothing was changed: ' + $item.path)
        }
        $replacePlan += [pscustomobject]@{ Path=$item.path; Source=$source; Destination=$destination; Original=$currentHash; Target=$item.sha256 }
    }
    foreach ($item in $manifest.deletions) {
        if ($item.path -cnotin $expectedDeletions -or $seen.ContainsKey($item.path)) {
            throw 'Update manifest contains an unexpected or duplicate deletion.'
        }
        $seen[$item.path] = $true
        foreach ($hash in @($item.allowed_sha256)) { Assert-Hash $hash }
        $destination = Get-ProjectFile $item.path
        if (-not [IO.File]::Exists((Get-FsPath $destination))) { continue }
        $currentHash = Get-Sha256 $destination
        if ($currentHash -cnotin @($item.allowed_sha256)) {
            throw ('An obsolete file has local edits. Nothing was changed: ' + $item.path)
        }
        $deletePlan += [pscustomobject]@{ Path=$item.path; Destination=$destination; Original=$currentHash }
    }
    $plan = @($replacePlan) + @($deletePlan)
    if ($plan.Count -eq 0) {
        Write-Host 'Already applied. No project files were changed.'
        exit 0
    }
    # Validation above is read-only. Back up every affected file before changing any source.
    $backup = Join-Path $script:Root ('EUNORA-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
    foreach ($item in $plan) {
        if ((Get-Sha256 $item.Destination) -cne $item.Original) { throw 'A project file changed during validation. Nothing was changed.' }
    }
    foreach ($item in $plan) {
        $backupPath = [IO.Path]::Combine($backup, $item.Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
        [void][IO.Directory]::CreateDirectory((Get-FsPath (Get-ParentPath $backupPath)))
        [IO.File]::Copy((Get-FsPath $item.Destination), (Get-FsPath $backupPath), $false)
        if ((Get-Sha256 $backupPath) -cne $item.Original) { throw 'Backup verification failed. Project sources were not changed.' }
    }
    try {
        foreach ($item in $replacePlan) {
            if ((Get-Sha256 $item.Destination) -cne $item.Original -or (Get-Sha256 $item.Source) -cne $item.Target) { throw 'A file changed after validation.' }
            [IO.File]::Copy((Get-FsPath $item.Source), (Get-FsPath $item.Destination), $true)
            if ((Get-Sha256 $item.Destination) -cne $item.Target) { throw 'Updated source verification failed.' }
            Write-Host ('UPDATED ' + $item.Path)
        }
        foreach ($item in $deletePlan) {
            if ((Get-Sha256 $item.Destination) -cne $item.Original) { throw 'A file changed after validation.' }
            [IO.File]::Delete((Get-FsPath $item.Destination))
            Write-Host ('REMOVED ' + $item.Path)
        }
    } catch {
        $failure = $_
        foreach ($item in $plan) {
            $backupPath = [IO.Path]::Combine($backup, $item.Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
            [IO.File]::Copy((Get-FsPath $backupPath), (Get-FsPath $item.Destination), $true)
        }
        throw ('Update failed; original sources were restored. ' + $failure.Exception.Message)
    }
    Write-Host ('Done. Updated: ' + $replacePlan.Count + '; removed: ' + $deletePlan.Count)
    Write-Host ('Backup: ' + $backup)
    Write-Host 'Build the project in Android Studio to install the updated app.'
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
