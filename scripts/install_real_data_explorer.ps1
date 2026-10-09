param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'Robin\explorer'),
    [string]$RuntimeRoot = (Join-Path $env:LOCALAPPDATA 'Robin\explorer-runtime'),
    [string]$PythonPath = '',
    [string]$StartupPath = '',
    [int]$Port = 4173,
    [int]$RefreshSeconds = 300,
    [switch]$SkipRegistration,
    [switch]$SkipStart
)

$ErrorActionPreference = 'Stop'

function Get-RobinFileHash {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($stream)
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Get-RobinRuntimeHash {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$RelativePaths
    )

    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $manifestLines = foreach ($relativePath in ($RelativePaths | Sort-Object)) {
        $runtimeFile = Join-Path $Root $relativePath
        if (-not (Test-Path -LiteralPath $runtimeFile -PathType Leaf)) {
            throw "ROBIN_EXPLORER_RUNTIME_FILE_MISSING:$runtimeFile"
        }
        $absolutePath = [System.IO.Path]::GetFullPath($runtimeFile)
        if (-not $absolutePath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ROBIN_EXPLORER_RUNTIME_PATH_ESCAPE:$absolutePath"
        }
        $normalizedPath = $absolutePath.Substring($rootPrefix.Length).Replace('\', '/')
        $fileHash = Get-RobinFileHash -Path $runtimeFile
        "$normalizedPath $fileHash"
    }
    $manifestText = [string]::Join(
        "`n",
        @('schema robin-real-data-explorer-runtime-v2') + @($manifestLines)
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($manifestText))
    }
    finally {
        $sha256.Dispose()
    }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Set-RobinStartupShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $shell = New-Object -ComObject WScript.Shell
    $suffix = [System.Guid]::NewGuid().ToString('N')
    $shortcutDirectory = Split-Path -Parent $Path
    $stagingDirectory = Join-Path (Split-Path -Parent $shortcutDirectory) '.RobinInstaller'
    New-Item -ItemType Directory -Force -Path $stagingDirectory | Out-Null
    $candidateShortcutPath = Join-Path $stagingDirectory ('candidate-' + $suffix + '.lnk')
    $backupShortcutPath = Join-Path $stagingDirectory ('backup-' + $suffix + '.lnk')
    try {
        $candidateShortcut = $shell.CreateShortcut($candidateShortcutPath)
        $candidateShortcut.TargetPath = $TargetPath
        $candidateShortcut.Arguments = $Arguments
        $candidateShortcut.WorkingDirectory = $WorkingDirectory
        $candidateShortcut.WindowStyle = 7
        $candidateShortcut.Description = 'Robin private real-data explorer on localhost'
        $candidateShortcut.Save()

        $validatedShortcut = $shell.CreateShortcut($candidateShortcutPath)
        $targetMatches = [System.IO.Path]::GetFullPath($validatedShortcut.TargetPath).Equals(
            [System.IO.Path]::GetFullPath($TargetPath),
            [System.StringComparison]::OrdinalIgnoreCase
        )
        $workingDirectoryMatches = [System.IO.Path]::GetFullPath(
            $validatedShortcut.WorkingDirectory
        ).Equals(
            [System.IO.Path]::GetFullPath($WorkingDirectory),
            [System.StringComparison]::OrdinalIgnoreCase
        )
        if (
            -not $targetMatches -or
            $validatedShortcut.Arguments -ne $Arguments -or
            -not $workingDirectoryMatches
        ) {
            throw 'ROBIN_EXPLORER_SHORTCUT_VALIDATION_FAILED'
        }

        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [System.IO.File]::Replace(
                $candidateShortcutPath,
                $Path,
                $backupShortcutPath,
                $true
            )
            Remove-Item -LiteralPath $backupShortcutPath -Force -ErrorAction SilentlyContinue
        }
        else {
            [System.IO.File]::Move($candidateShortcutPath, $Path)
        }
    }
    finally {
        Remove-Item -LiteralPath $candidateShortcutPath -Force -ErrorAction SilentlyContinue
    }
}

function Test-RobinExplorerProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][int]$Port
    )

    if (-not (@('python.exe', 'pythonw.exe') -contains $Process.Name) -or -not $Process.CommandLine) {
        return $false
    }
    $commandPattern = (
        '^\s*(?:"[^"]+"|\S+)\s+-B\s+"(?<launcher>[^"]+)"' +
        '\s+--root\s+"(?<root>[^"]+)"' +
        '\s+--port\s+(?<port>\d+)' +
        '\s+--refresh-seconds\s+\d+\s*$'
    )
    $match = [Regex]::Match(
        $Process.CommandLine,
        $commandPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if (-not $match.Success) {
        return $false
    }
    try {
        $runtimePrefix = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\') + '\'
        $releasePrefix = [System.IO.Path]::GetFullPath(
            (Join-Path $runtimePrefix 'releases')
        ).TrimEnd('\') + '\'
        $launcher = [System.IO.Path]::GetFullPath($match.Groups['launcher'].Value)
        $dataAbsolute = [System.IO.Path]::GetFullPath($DataRoot)
        $processDataRoot = [System.IO.Path]::GetFullPath($match.Groups['root'].Value)
    }
    catch {
        return $false
    }
    if (-not $launcher.StartsWith($releasePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $relativeLauncher = $launcher.Substring($releasePrefix.Length).Replace('/', '\')
    $launcherMatches = [Regex]::IsMatch(
        $relativeLauncher,
        '^[0-9a-f]{64}\\scripts\\run_real_data_explorer\.py$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    $rootMatches = $processDataRoot.Equals(
        $dataAbsolute,
        [System.StringComparison]::OrdinalIgnoreCase
    )
    $portMatches = $match.Groups['port'].Value -eq [string]$Port
    return $launcherMatches -and $rootMatches -and $portMatches
}

function Get-RobinExplorerProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][int]$Port
    )

    return @(
        Get-CimInstance Win32_Process |
            Where-Object { @('python.exe', 'pythonw.exe') -contains $_.Name } |
            Where-Object {
                Test-RobinExplorerProcess -Process $_ -RuntimeRoot $RuntimeRoot -DataRoot $DataRoot -Port $Port
            }
    )
}

function Stop-RobinExplorerProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSeconds = 10
    )

    $processes = @(Get-RobinExplorerProcesses -RuntimeRoot $RuntimeRoot -DataRoot $DataRoot -Port $Port)
    foreach ($process in ($processes | Sort-Object ProcessId -Descending)) {
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $remaining = @(
            Get-RobinExplorerProcesses -RuntimeRoot $RuntimeRoot -DataRoot $DataRoot -Port $Port
        )
        if ($remaining.Count -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'ROBIN_EXPLORER_PROCESS_RETIREMENT_TIMEOUT'
}

$taskName = 'RobinRealDataExplorer'
$startup = if ($StartupPath) { $StartupPath } else { [Environment]::GetFolderPath('Startup') }
$shortcutPath = Join-Path $startup "$taskName.lnk"
$managedCheckoutPattern = [Regex]::Escape((Join-Path ('.' + 'codex') 'worktrees'))
$python = $PythonPath
if (-not $python) {
    $pythonCandidates = @()
    if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
        $shell = New-Object -ComObject WScript.Shell
        $existingShortcut = $shell.CreateShortcut($shortcutPath)
        $pythonCandidates += $existingShortcut.TargetPath
    }
    $pythonCandidates += @(
        (Join-Path $RepositoryRoot '.venv\Scripts\pythonw.exe'),
        (Join-Path $RepositoryRoot '.venv\Scripts\python.exe')
    )
    $python = $pythonCandidates |
        Where-Object {
            $_ -and
            (Test-Path -LiteralPath $_ -PathType Leaf) -and
            ([System.IO.Path]::GetFullPath($_) -notmatch $managedCheckoutPattern)
        } |
        Select-Object -First 1
    if (-not $python) {
        if ($pythonCandidates | Where-Object { $_ -and ([System.IO.Path]::GetFullPath($_) -match $managedCheckoutPattern) }) {
            throw 'ROBIN_EXPLORER_PYTHON_WORKTREE_FORBIDDEN'
        }
        throw 'ROBIN_EXPLORER_PYTHON_NOT_FOUND'
    }
}
if ([System.IO.Path]::GetFullPath($python) -match $managedCheckoutPattern) {
    throw 'ROBIN_EXPLORER_PYTHON_WORKTREE_FORBIDDEN'
}
$launcher = Join-Path $RepositoryRoot 'scripts\run_real_data_explorer.py'
$ghLauncher = Join-Path $RepositoryRoot 'scripts\invoke_gh_hidden.ps1'
if (
    -not (Test-Path -LiteralPath $python -PathType Leaf) -or
    -not (Test-Path -LiteralPath $launcher -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ghLauncher -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $RepositoryRoot 'src\robin') -PathType Container)
) {
    throw 'ROBIN_EXPLORER_RUNTIME_NOT_FOUND'
}
$trackedPaths = @(
    & git -C $RepositoryRoot ls-files -- 'scripts/run_real_data_explorer.py' 'scripts/invoke_gh_hidden.ps1' 'src/robin'
)
if ($LASTEXITCODE -ne 0 -or $trackedPaths.Count -eq 0) {
    throw 'ROBIN_EXPLORER_TRACKED_RUNTIME_NOT_FOUND'
}
$trackedPaths = @($trackedPaths | ForEach-Object { $_.Replace('/', '\') } | Sort-Object -Unique)
if ($trackedPaths -notcontains 'scripts\run_real_data_explorer.py') {
    throw 'ROBIN_EXPLORER_LAUNCHER_NOT_TRACKED'
}
if ($trackedPaths -notcontains 'scripts\invoke_gh_hidden.ps1') {
    throw 'ROBIN_EXPLORER_GH_LAUNCHER_NOT_TRACKED'
}

New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
$runtimeHash = Get-RobinRuntimeHash -Root $RepositoryRoot -RelativePaths $trackedPaths
$releasesRoot = Join-Path $RuntimeRoot 'releases'
$runtimeRelease = Join-Path $releasesRoot $runtimeHash
$readyMarker = Join-Path $runtimeRelease '.ready'
if (-not (Test-Path -LiteralPath $readyMarker -PathType Leaf)) {
    if (Test-Path -LiteralPath $runtimeRelease) {
        throw "ROBIN_EXPLORER_RUNTIME_INCOMPLETE:$runtimeRelease"
    }
    New-Item -ItemType Directory -Force -Path $RuntimeRoot, $releasesRoot | Out-Null
    $stage = Join-Path $RuntimeRoot ('.staging-' + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    foreach ($relativePath in $trackedPaths) {
        $sourcePath = Join-Path $RepositoryRoot $relativePath
        $destinationPath = Join-Path $stage $relativePath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destinationPath) | Out-Null
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath
    }
    [ordered]@{
        schema_version = 'robin-real-data-explorer-runtime-v2'
        runtime_hash = $runtimeHash
        file_count = $trackedPaths.Count
        files = @($trackedPaths | ForEach-Object { $_.Replace('\', '/') })
        source_layout = 'scripts/run_real_data_explorer.py+scripts/invoke_gh_hidden.ps1+src/robin'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stage 'runtime-manifest.json') -Encoding utf8
    New-Item -ItemType File -Path (Join-Path $stage '.ready') | Out-Null
    Move-Item -LiteralPath $stage -Destination $runtimeRelease
}

$runtimeManifest = Get-Content -LiteralPath (Join-Path $runtimeRelease 'runtime-manifest.json') -Raw | ConvertFrom-Json
if ($runtimeManifest.runtime_hash -ne $runtimeHash) {
    throw "ROBIN_EXPLORER_RUNTIME_MANIFEST_MISMATCH:$runtimeRelease"
}
$installedRuntimeHash = Get-RobinRuntimeHash -Root $runtimeRelease -RelativePaths $trackedPaths
if ($installedRuntimeHash -ne $runtimeHash) {
    throw "ROBIN_EXPLORER_RUNTIME_HASH_MISMATCH:$runtimeRelease"
}
$installedLauncher = Join-Path $runtimeRelease 'scripts\run_real_data_explorer.py'
$validationPython = Join-Path (Split-Path -Parent $python) 'python.exe'
if (-not (Test-Path -LiteralPath $validationPython -PathType Leaf)) {
    $validationPython = $python
}
& $validationPython -B $installedLauncher --help *> $null
if ($LASTEXITCODE -ne 0) {
    throw "ROBIN_EXPLORER_RUNTIME_IMPORT_FAILED:$runtimeRelease"
}

$arguments = @(
    '-B',
    ('"{0}"' -f $installedLauncher),
    '--root', ('"{0}"' -f $DataRoot),
    '--port', $Port,
    '--refresh-seconds', $RefreshSeconds
) -join ' '
$mode = 'Unregistered'
if (-not $SkipRegistration) {
    if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
        $mode = 'StartupShortcut'
        Set-RobinStartupShortcut -Path $shortcutPath -TargetPath $python -Arguments $arguments -WorkingDirectory $runtimeRelease
    }
    else {
        $action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $runtimeRelease
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 3650)
        $mode = 'ScheduledTask'
        try {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description 'Robin private real-data explorer on localhost' -Force -ErrorAction Stop | Out-Null
        }
        catch {
            $existingTask = $null
            try {
                $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            }
            catch {
                if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound_TaskName,*') {
                    throw 'ROBIN_EXPLORER_SCHEDULED_TASK_INSPECTION_FAILED'
                }
            }
            if ($existingTask) {
                throw 'ROBIN_EXPLORER_EXISTING_SCHEDULED_TASK_UPDATE_FAILED'
            }
            $mode = 'StartupShortcut'
            Set-RobinStartupShortcut -Path $shortcutPath -TargetPath $python -Arguments $arguments -WorkingDirectory $runtimeRelease
        }
    }
}

if (-not $SkipStart) {
    if ($mode -notin @('ScheduledTask', 'StartupShortcut')) {
        throw 'ROBIN_EXPLORER_START_REQUIRES_REGISTRATION'
    }
    Stop-RobinExplorerProcesses -RuntimeRoot $RuntimeRoot -DataRoot $DataRoot -Port $Port
    if ($mode -eq 'ScheduledTask') {
        Start-ScheduledTask -TaskName $taskName
    }
    else {
        Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $runtimeRelease -WindowStyle Hidden
    }
}

[pscustomobject]@{
    TaskName = $taskName
    Mode = $mode
    Url = "http://127.0.0.1:$Port/robin-real-data.html"
    DataRoot = $DataRoot
    RuntimeRoot = $RuntimeRoot
    RuntimeRelease = $runtimeRelease
    RuntimeHash = $runtimeHash
    PythonPath = $python
    RefreshSeconds = $RefreshSeconds
}
