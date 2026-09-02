[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'
$installer = (Resolve-Path -LiteralPath $InstallerPath).Path
$tempBase = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) 'SoftcurseBlackwatch-InstallerTests'))
$testRoot = [System.IO.Path]::GetFullPath((Join-Path $tempBase ([guid]::NewGuid().ToString('N'))))
$installDirectory = Join-Path $testRoot 'installed'
$outsideMarker = Join-Path $testRoot 'outside-installer-ownership.txt'
$insideMarker = Join-Path $installDirectory 'user-created-file.txt'
$installLog = Join-Path $testRoot 'install.log'
$repairLog = Join-Path $testRoot 'repair.log'
$uninstallLog = Join-Path $testRoot 'uninstall.log'
$uninstallRegistryPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{7010568A-8183-410E-9E54-C9388DBE65F5}_is1'

function Invoke-Process([string]$FilePath, [string[]]$Arguments, [string]$Name) {
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$Name failed with exit code $($process.ExitCode)."
    }
}

function Invoke-Install([string]$LogPath) {
    Invoke-Process $installer @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/NOICONS',
        "/DIR=$installDirectory", "/LOG=$LogPath"
    ) 'Blackwatch installer'
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
Set-Content -LiteralPath $outsideMarker -Value 'must survive installer lifecycle' -Encoding utf8NoBOM

try {
    Invoke-Install $installLog

    $executable = Join-Path $installDirectory 'Softcurse.Blackwatch.exe'
    $uninstaller = Join-Path $installDirectory 'unins000.exe'
    if (-not (Test-Path -LiteralPath $executable) -or -not (Test-Path -LiteralPath $uninstaller)) {
        throw 'Installer did not produce the expected executable and uninstaller.'
    }
    if (-not (Test-Path -LiteralPath $uninstallRegistryPath)) {
        throw 'Installer did not register its per-user uninstaller.'
    }

    Invoke-Process $executable @('--self-test') 'Installed application self-test'

    # Same-AppId repair follows the in-place path that version upgrades use.
    Invoke-Install $repairLog
    Invoke-Process $executable @('--self-test') 'Repaired application self-test'

    Set-Content -LiteralPath $insideMarker -Value 'not owned by installer' -Encoding utf8NoBOM
    Invoke-Process $uninstaller @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=$uninstallLog"
    ) 'Blackwatch uninstaller'

    if (Test-Path -LiteralPath $executable) {
        throw 'Uninstall left the Blackwatch executable behind.'
    }
    if (Test-Path -LiteralPath $uninstallRegistryPath) {
        throw 'Uninstall left its registry registration behind.'
    }
    if (-not (Test-Path -LiteralPath $outsideMarker) -or -not (Test-Path -LiteralPath $insideMarker)) {
        throw 'Uninstall removed a file outside installer ownership.'
    }

    Write-Host 'Installer lifecycle passed: install, self-test, repair, uninstall, registry cleanup, and ownership boundaries.'
}
catch {
    foreach ($log in @($installLog, $repairLog, $uninstallLog)) {
        if (Test-Path -LiteralPath $log) {
            Write-Host "--- $([System.IO.Path]::GetFileName($log)) ---"
            Get-Content -LiteralPath $log -Tail 80
        }
    }
    throw
}
finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $requiredPrefix = $tempBase.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($resolvedRoot.StartsWith($requiredPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
