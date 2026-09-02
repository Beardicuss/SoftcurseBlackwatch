[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$projectRoot = [string]$PSScriptRoot
$publishPath = [string](Join-Path $projectRoot 'publish')
$outputPath = [string](Join-Path $projectRoot 'output')
$version = '0.1.0-alpha'

function Invoke-Checked([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory = $projectRoot) {
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$FilePath failed with exit code $LASTEXITCODE." }
    }
    finally { Pop-Location }
}

if (Test-Path -LiteralPath $publishPath) { Remove-Item -LiteralPath $publishPath -Recurse -Force }
if (Test-Path -LiteralPath $outputPath) { Remove-Item -LiteralPath $outputPath -Recurse -Force }
New-Item -ItemType Directory -Path $publishPath, $outputPath | Out-Null

Invoke-Checked 'npm' @('ci', '--no-audit', '--no-fund') (Join-Path $projectRoot 'Frontend')
Invoke-Checked 'npm' @('run', 'audit') (Join-Path $projectRoot 'Frontend')
Invoke-Checked 'npm' @('run', 'lint') (Join-Path $projectRoot 'Frontend')
Invoke-Checked 'npm' @('test', '--', '--run') (Join-Path $projectRoot 'Frontend')
Invoke-Checked 'dotnet' @('restore', 'SoftcurseBlackwatch.sln')
Invoke-Checked 'dotnet' @('restore', 'Softcurse.UI\Softcurse.UI.csproj', '-r', 'win-x64')
Invoke-Checked 'dotnet' @('tool', 'restore')
Invoke-Checked 'dotnet' @('test', 'SoftcurseBlackwatch.sln', '-c', $Configuration, '--no-restore')
Invoke-Checked 'dotnet' @(
    'publish', 'Softcurse.UI\Softcurse.UI.csproj',
    '-c', $Configuration, '-r', 'win-x64', '--self-contained', 'true',
    '--no-restore', '-o', $publishPath
)

Invoke-Checked 'dotnet' @(
    'sbom-tool', 'generate',
    '-b', $publishPath,
    '-bc', $projectRoot,
    '-pn', 'Softcurse Blackwatch',
    '-pv', $version,
    '-ps', 'Softcurse Inc.',
    '-nsb', 'https://github.com/Beardicuss/SoftcurseBlackwatch'
)
$sbom = Get-ChildItem -LiteralPath (Join-Path $publishPath '_manifest') -Recurse -File -Filter '*.spdx.json' | Select-Object -First 1
if (-not $sbom) { throw 'SBOM generation completed without producing an SPDX manifest.' }
$sbomDocument = Get-Content -LiteralPath $sbom.FullName -Raw | ConvertFrom-Json
if (@($sbomDocument.packages).Count -le 1 -or @($sbomDocument.files).Count -eq 0 -or @($sbomDocument.relationships).Count -le 1) {
    throw 'SBOM validation failed because dependency packages, shipped files, or relationships are missing.'
}
Copy-Item -LiteralPath $sbom.FullName -Destination (Join-Path $outputPath "SoftcurseBlackwatch-$version.spdx.json")

$archivePath = Join-Path $outputPath "SoftcurseBlackwatch-$version-win-x64.zip"
Compress-Archive -Path (Join-Path $publishPath '*') -DestinationPath $archivePath -CompressionLevel Optimal

if (-not $SkipInstaller) {
    $compilerCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $compiler = $compilerCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $compiler) { throw 'Inno Setup 6 compiler was not found. Install Inno Setup 6.7.1 or use -SkipInstaller.' }
    Invoke-Checked $compiler @('SoftcurseBlackwatch.iss')
}

$checksumFiles = Get-ChildItem -LiteralPath $outputPath -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Sort-Object Name
$checksumLines = foreach ($file in $checksumFiles) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($file.Name)"
}
Set-Content -LiteralPath (Join-Path $outputPath 'SHA256SUMS.txt') -Value $checksumLines -Encoding utf8NoBOM
Write-Host "Blackwatch $version artifacts created in $outputPath"
