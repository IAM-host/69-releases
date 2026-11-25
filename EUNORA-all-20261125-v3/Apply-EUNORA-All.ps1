[CmdletBinding()]
param([string]$ProjectRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:IsWindowsFileSystem = [IO.Path]::DirectorySeparatorChar -eq '\'

function Get-FsPath([string]$Path) {
    if ($script:IsWindowsFileSystem -and -not $Path.StartsWith('\\?\')) {
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
function Get-FullPath([string]$Path) {
    if ($script:IsWindowsFileSystem) {
        $Path = $Path.Replace('/', '\')
        if ($Path.StartsWith('\\.\')) { throw 'Windows device paths are not supported.' }
        if ($Path.StartsWith('\\?\')) {
            if ($Path -notmatch '^\\\\\?\\(?:[A-Za-z]:\\|UNC\\[^\\]+\\[^\\]+(?:\\|$))') {
                throw 'Unsupported extended Windows path.'
            }
        } elseif ($Path.StartsWith('\\')) {
            $Path = Get-FsPath $Path
        } elseif ($Path -match '^[A-Za-z]:\\') {
            $Path = Get-FsPath $Path
        } else {
            if ($Path.StartsWith('\') -or $Path.Contains(':')) { throw 'Use a full project path or a normal relative path.' }
            $Path = Get-FsPath ([IO.Path]::Combine((Get-Location).ProviderPath, $Path))
        }
    }
    # Prefix before GetFullPath, not just before file I/O, for Windows PowerShell 5.1.
    $full = Get-DisplayPath ([IO.Path]::GetFullPath($Path))
    $root = Get-DisplayPath ([IO.Path]::GetPathRoot((Get-FsPath $full)))
    if ($full.Length -gt $root.Length) { $full = $full.TrimEnd([IO.Path]::DirectorySeparatorChar) }
    return $full
}
function Get-ParentPath([string]$Path) {
    return Get-DisplayPath ([IO.Path]::GetDirectoryName((Get-FsPath $Path)))
}
function Assert-SafePath([string]$Path) {
    # Check every ancestor, including the project/bundle roots and broken links.
    $node = $Path
    while (-not [string]::IsNullOrEmpty($node)) {
        try {
            $attributes = [IO.File]::GetAttributes((Get-FsPath $node))
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('Symbolic links and junctions are not supported: ' + $node)
            }
        } catch {
            $cause = $_.Exception
            if ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
            if ($cause -isnot [IO.FileNotFoundException] -and $cause -isnot [IO.DirectoryNotFoundException]) { throw }
        }
        $parent = Get-ParentPath $node
        if ($parent -eq $node) { break }
        $node = $parent
    }
}
function Get-ChildPath([string]$Root, [string]$Relative) {
    if ([string]::IsNullOrEmpty($Relative) -or $Relative -cnotmatch '^[A-Za-z0-9_. -]+(?:/[A-Za-z0-9_. -]+)*$' -or
        @($Relative.Split('/') | Where-Object { $_ -eq '.' -or $_ -eq '..' -or $_.Trim() -cne $_ -or $_.EndsWith('.') }).Count -gt 0) {
        throw 'Unsafe relative path in update manifest.'
    }
    $result = Get-FullPath ([IO.Path]::Combine((Get-FsPath $Root), $Relative.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    $prefix = $Root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $comparison = [StringComparison]::Ordinal
    if ($script:IsWindowsFileSystem) { $comparison = [StringComparison]::OrdinalIgnoreCase }
    if (-not $result.StartsWith($prefix, $comparison)) { throw 'Update path is outside its permitted folder.' }
    Assert-SafePath $result
    return $result
}
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead((Get-FsPath $Path))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}
function Assert-Hash($Hash) {
    if ($Hash -isnot [string] -or $Hash -cnotmatch '^[a-f0-9]{64}$') { throw 'Invalid SHA-256 value in update manifest.' }
}
function Assert-Properties($Object, [string[]]$Names) {
    if ($Object -isnot [pscustomobject]) { throw 'Invalid update manifest object.' }
    $actual = @($Object.PSObject.Properties.Name)
    if ($actual.Count -ne $Names.Count) { throw 'Unexpected update manifest properties.' }
    foreach ($name in $actual) {
        if ($name -cnotin $Names) { throw 'Unexpected update manifest property.' }
    }
}
function Assert-CurrentState($Item) {
    Assert-SafePath $Item.Destination
    if ([IO.Directory]::Exists((Get-FsPath $Item.Destination))) { throw ('A directory occupies a file path: ' + $Item.Path) }
    $exists = [IO.File]::Exists((Get-FsPath $Item.Destination))
    if ($exists -ne $Item.Existed) { throw ('A project file appeared or disappeared during validation: ' + $Item.Path) }
    if ($exists -and (Get-Sha256 $Item.Destination) -cne $Item.Original) { throw ('A project file changed during validation: ' + $Item.Path) }
}
function Assert-SourceState($Item) {
    Assert-SafePath $Item.Source
    if (-not [IO.File]::Exists((Get-FsPath $Item.Source)) -or (Get-Sha256 $Item.Source) -cne $Item.Target) {
        throw ('Missing or modified update source: ' + $Item.Path)
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        $ProjectRoot = Read-Host 'EUNORA project folder (contains gradlew and app)'
    }
    $ProjectRoot = $ProjectRoot.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { throw 'No project folder was provided.' }
    $root = Get-FullPath $ProjectRoot
    $bundleRoot = Get-FullPath $PSScriptRoot
    Assert-SafePath $root
    Assert-SafePath $bundleRoot
    foreach ($required in @('gradlew', 'app/src/main/java/com/example/wheelprobe/ModuleMain.kt')) {
        if (-not [IO.File]::Exists((Get-FsPath (Get-ChildPath $root $required)))) {
            throw ('Not an EUNORA project folder. Missing: ' + $required)
        }
    }
    $requiredExisting = @(
        'app/src/main/java/com/example/wheelprobe/E02.kt',
        'app/src/main/java/com/example/wheelprobe/E03.kt',
        'app/src/main/java/com/example/wheelprobe/E04.kt',
        'app/src/main/java/com/example/wheelprobe/E06.kt',
        'app/src/main/java/com/example/wheelprobe/E05.kt',
        'app/src/main/java/com/example/wheelprobe/ModuleMain.kt',
        'app/proguard-rules.pro'
    )
    $allowedPaths = @($requiredExisting) + @(
        'app/src/main/resources/META-INF/xposed/native_init.list',
        'app/src/main/cpp/eunora_logi_native.c',
        'app/src/main/cpp/eunora_logi_native.h',
        'app/src/main/jniLibs/arm64-v8a/libeunora_logi_native.so',
        'app/src/main/jniLibs/armeabi-v7a/libeunora_logi_native.so',
        'app/src/main/jniLibs/x86/libeunora_logi_native.so',
        'app/src/main/jniLibs/x86_64/libeunora_logi_native.so',
        'tools/build_logi_native.py'
    )
    $allowedDeletions = @(
        'app/src/main/java/com/example/wheelprobe/AutoClickService.kt',
        'app/src/main/java/com/example/wheelprobe/ExecutionClient.kt',
        'app/src/main/res/xml/eunora_accessibility_service.xml',
        'app/src/main/java/com/example/wheelprobe/package com/example/wheelprobe  import android/content/BroadcastReceiver import android/content/Context import android/content/Intent import android/util/ErrorReporter.kt'
    )
    $manifestPath = Get-ChildPath $bundleRoot 'update-manifest.json'
    $manifestText = [IO.File]::ReadAllText((Get-FsPath $manifestPath))
    if (-not $manifestText.TrimStart().StartsWith('{')) { throw 'The update manifest must be a JSON object.' }
    $manifest = $manifestText | ConvertFrom-Json
    Assert-Properties $manifest @('files', 'deletions')
    if ($manifest.files -isnot [Array] -or @($manifest.files).Count -ne $allowedPaths.Count) { throw 'The manifest must contain exactly the 15 supported files.' }
    if ($manifest.deletions -isnot [Array] -or @($manifest.deletions).Count -ne $allowedDeletions.Count) { throw 'The manifest must contain exactly the 4 supported deletions.' }
    $seen = @{}
    $all = @()
    foreach ($item in $manifest.files) {
        Assert-Properties $item @('path', 'sha256', 'allowed_old_sha256', 'allow_missing')
        if ($item.path -isnot [string] -or $item.path -cnotin $allowedPaths -or $seen.ContainsKey($item.path)) {
            throw 'The manifest contains an unsupported or duplicate file path.'
        }
        $seen[$item.path] = $true
        Assert-Hash $item.sha256
        if ($item.allowed_old_sha256 -isnot [Array] -or $item.allow_missing -isnot [bool]) { throw 'Invalid manifest hash list or allow_missing flag.' }
        foreach ($hash in $item.allowed_old_sha256) { Assert-Hash $hash }
        $mustExist = $item.path -cin $requiredExisting
        if ($item.allow_missing -eq $mustExist) { throw ('Incorrect allow_missing flag for: ' + $item.path) }
        $source = Get-ChildPath $bundleRoot $item.path
        $destination = Get-ChildPath $root $item.path
        $comparison = [StringComparison]::Ordinal
        if ($script:IsWindowsFileSystem) { $comparison = [StringComparison]::OrdinalIgnoreCase }
        if ($source.Equals($destination, $comparison)) { throw 'Extract this update outside the project source paths.' }
        if ([IO.Directory]::Exists((Get-FsPath $destination))) { throw ('A directory occupies a file path: ' + $item.path) }
        $exists = [IO.File]::Exists((Get-FsPath $destination))
        $current = $null
        if ($exists) {
            $current = Get-Sha256 $destination
            if ($current -cne $item.sha256 -and $current -cnotin $item.allowed_old_sha256) {
                throw ('Unrecognized local file. Nothing was changed: ' + $item.path)
            }
        } elseif ($mustExist) { throw ('Missing required project file: ' + $item.path) }
        $entry = [pscustomobject]@{ Path=$item.path; Source=$source; Destination=$destination; Existed=$exists; Original=$current; Target=$item.sha256; Backup=$null }
        Assert-SourceState $entry
        $all += $entry
    }
    $deleteAll = @()
    foreach ($item in $manifest.deletions) {
        Assert-Properties $item @('path', 'allowed_old_sha256')
        if ($item.path -isnot [string] -or $item.path -cnotin $allowedDeletions -or $seen.ContainsKey($item.path)) {
            throw 'The manifest contains an unsupported or duplicate deletion path.'
        }
        $seen[$item.path] = $true
        if ($item.allowed_old_sha256 -isnot [Array] -or $item.allowed_old_sha256.Count -eq 0) { throw 'Invalid deletion hash list.' }
        foreach ($hash in $item.allowed_old_sha256) { Assert-Hash $hash }
        $destination = Get-ChildPath $root $item.path
        if ([IO.Directory]::Exists((Get-FsPath $destination))) { throw ('A directory occupies a deletion path: ' + $item.path) }
        $exists = [IO.File]::Exists((Get-FsPath $destination))
        $current = $null
        if ($exists) {
            $current = Get-Sha256 $destination
            if ($current -cnotin $item.allowed_old_sha256) { throw ('Unrecognized obsolete file. Nothing was changed: ' + $item.path) }
        }
        $deleteAll += [pscustomobject]@{ Path=$item.path; Destination=$destination; Existed=$exists; Original=$current; Backup=$null }
    }
    $plan = @($all | Where-Object { $_.Original -cne $_.Target })
    $deletePlan = @($deleteAll | Where-Object { $_.Existed })
    if ($plan.Count -eq 0 -and $deletePlan.Count -eq 0) {
        Write-Host 'Already applied. No project files were changed.'
        exit 0
    }
    # Every input and current target has been checked before the first write.
    foreach ($item in $all) { Assert-SourceState $item; Assert-CurrentState $item }
    foreach ($item in $deleteAll) { Assert-CurrentState $item }
    $backupName = 'EUNORA-all-backup-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString('N')
    $backup = Get-ChildPath $root $backupName
    if ([IO.Directory]::Exists((Get-FsPath $backup)) -or [IO.File]::Exists((Get-FsPath $backup))) { throw 'Backup path already exists.' }
    [void][IO.Directory]::CreateDirectory((Get-FsPath $backup))
    $backupPlan = @($plan | Where-Object { $_.Existed }) + @($deletePlan)
    foreach ($item in $backupPlan) {
        Assert-CurrentState $item
        $item.Backup = Get-ChildPath $backup $item.Path
        [void][IO.Directory]::CreateDirectory((Get-FsPath (Get-ParentPath $item.Backup)))
        [IO.File]::Copy((Get-FsPath $item.Destination), (Get-FsPath $item.Backup), $false)
        if ((Get-Sha256 $item.Backup) -cne $item.Original) { throw 'Backup verification failed. Project files were not changed.' }
    }
    $created = @($plan | Where-Object { -not $_.Existed } | ForEach-Object { $_.Path })
    $record = [ordered]@{
        created_utc = [DateTime]::UtcNow.ToString('o')
        planned_new_paths = $created
        planned_deletions = @($deletePlan | ForEach-Object { [ordered]@{ path=$_.Path; original_sha256=$_.Original } })
        changed_existing = @($plan | Where-Object { $_.Existed } | ForEach-Object { [ordered]@{ path=$_.Path; original_sha256=$_.Original; updated_sha256=$_.Target } })
    }
    $recordPath = Get-ChildPath $backup 'apply-record.json'
    [IO.File]::WriteAllText((Get-FsPath $recordPath), ($record | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    $touchedExisting = New-Object 'System.Collections.Generic.List[object]'
    $createdByRun = New-Object 'System.Collections.Generic.List[object]'
    try {
        # Recheck the full set after backups, before touching any project source.
        foreach ($item in $all) { Assert-SourceState $item; Assert-CurrentState $item }
        foreach ($item in $deleteAll) { Assert-CurrentState $item }
        foreach ($item in $plan) {
            Assert-SourceState $item
            Assert-CurrentState $item
            $parent = Get-ParentPath $item.Destination
            Assert-SafePath $parent
            [void][IO.Directory]::CreateDirectory((Get-FsPath $parent))
            Assert-SafePath $item.Destination
            if ($item.Existed) {
                [void]$touchedExisting.Add($item)
                [IO.File]::Copy((Get-FsPath $item.Source), (Get-FsPath $item.Destination), $true)
            } else {
                # CreateNew refuses an unexpected concurrent file; record only files we created.
                $output = [IO.File]::Open((Get-FsPath $item.Destination), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                [void]$createdByRun.Add($item)
                try {
                    $inputStream = [IO.File]::OpenRead((Get-FsPath $item.Source))
                    try { $inputStream.CopyTo($output) } finally { $inputStream.Dispose() }
                } finally { $output.Dispose() }
            }
            if ((Get-Sha256 $item.Destination) -cne $item.Target) { throw ('Updated file verification failed: ' + $item.Path) }
            Write-Host ('UPDATED ' + $item.Path)
        }
        foreach ($item in $deletePlan) {
            Assert-CurrentState $item
            [void]$touchedExisting.Add($item)
            [IO.File]::Delete((Get-FsPath $item.Destination))
            if ([IO.File]::Exists((Get-FsPath $item.Destination))) { throw ('Obsolete file removal failed: ' + $item.Path) }
            Write-Host ('REMOVED ' + $item.Path)
        }
        foreach ($item in $all) {
            Assert-SourceState $item
            Assert-SafePath $item.Destination
            if ((Get-Sha256 $item.Destination) -cne $item.Target) { throw ('Final verification failed: ' + $item.Path) }
        }
        foreach ($item in $deleteAll) {
            Assert-SafePath $item.Destination
            if ([IO.File]::Exists((Get-FsPath $item.Destination)) -or [IO.Directory]::Exists((Get-FsPath $item.Destination))) {
                throw ('Final deletion verification failed: ' + $item.Path)
            }
        }
    } catch {
        $failure = $_.Exception.Message
        $rollbackFailures = @()
        foreach ($item in $touchedExisting) {
            try {
                Assert-SafePath $item.Destination
                Assert-SafePath $item.Backup
                if ((Get-Sha256 $item.Backup) -cne $item.Original) { throw 'Backup changed.' }
                [IO.File]::Copy((Get-FsPath $item.Backup), (Get-FsPath $item.Destination), $true)
                if ((Get-Sha256 $item.Destination) -cne $item.Original) { throw 'Restored file verification failed.' }
            } catch { $rollbackFailures += $item.Path }
        }
        foreach ($item in $createdByRun) {
            try {
                Assert-SafePath $item.Destination
                [IO.File]::Delete((Get-FsPath $item.Destination))
                if ([IO.File]::Exists((Get-FsPath $item.Destination))) { throw 'New file removal failed.' }
            } catch { $rollbackFailures += $item.Path }
        }
        if ($rollbackFailures.Count -gt 0) {
            throw ('Update failed. Automatic rollback needs manual recovery for: ' + ($rollbackFailures -join ', ') + '. Backup: ' + $backup + '. Cause: ' + $failure)
        }
        throw ('Update failed; changed existing files were restored and files created by this run were removed. Backup: ' + $backup + '. Cause: ' + $failure)
    }
    Write-Host ('Done. Updated or added: ' + $plan.Count + '; removed: ' + $deletePlan.Count)
    Write-Host ('Backup: ' + $backup)
    Write-Host 'Open this project in Android Studio and build the updated app.'
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
