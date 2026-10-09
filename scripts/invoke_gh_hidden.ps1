param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $GhArgs
)

$ErrorActionPreference = 'Stop'

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $quoted = '"'
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes += 1
            continue
        }
        if ($character -eq '"') {
            for ($index = 0; $index -lt (($backslashes * 2) + 1); $index += 1) {
                $quoted += '\'
            }
            $quoted += '"'
        }
        else {
            for ($index = 0; $index -lt $backslashes; $index += 1) {
                $quoted += '\'
            }
            $quoted += $character
        }
        $backslashes = 0
    }
    for ($index = 0; $index -lt ($backslashes * 2); $index += 1) {
        $quoted += '\'
    }
    return $quoted + '"'
}

$ghCommand = Get-Command gh.exe -ErrorAction Stop
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $ghCommand.Source
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
if ($null -ne $startInfo.ArgumentList) {
    foreach ($argument in $GhArgs) {
        [void] $startInfo.ArgumentList.Add($argument)
    }
}
else {
    $startInfo.Arguments = @(
        $GhArgs | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value $_ }
    ) -join ' '
}

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
[void] $process.Start()
$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
$process.WaitForExit()
$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()

if ($stdout) {
    Write-Output -NoEnumerate $stdout
}
if ($stderr) {
    [Console]::Error.Write($stderr)
}
exit $process.ExitCode
