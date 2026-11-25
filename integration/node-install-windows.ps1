#Requires -Version 7.0
param(
    [Parameter(Mandatory = $true)] [string] $Client,
    [Parameter(Mandatory = $true)] [string] $Daemon,
    [Parameter(Mandatory = $true)] [string] $Compat
)

$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Windows installation fixture requires Windows.' }
$clientAsset = Get-Item -LiteralPath $Client
$daemonAsset = Get-Item -LiteralPath $Daemon
$compatAsset = Get-Item -LiteralPath $Compat
$installer = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/install-node.ps1'
$shell = (Get-Command pwsh -CommandType Application).Source
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('laneway-install-test-' + [guid]::NewGuid().ToString('N'))
$bin = Join-Path $work 'Laneway\bin'
$state = Join-Path $work 'Laneway\rootless'
$root = $env:LOCALAPPDATA
$path = $env:Path

function New-Stage {
    $stage = Join-Path $bin ('.laneway-stage-' + [guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($stage) | Out-Null
    $lines = foreach ($asset in @($clientAsset, $daemonAsset, $compatAsset)) {
        $file = Join-Path $stage $asset.Name
        Copy-Item -LiteralPath $asset.FullName -Destination $file
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $asset.Name
    }
    Set-Content -LiteralPath (Join-Path $stage 'checksums.txt') -Value $lines
    Set-Content -LiteralPath (Join-Path $stage 'checksums.sigstore.json') -Value 'fixture-signature'
    return $stage
}

function Assert-CompleteInstall {
    foreach ($item in @(@('laneway.exe', $clientAsset), @('lanewayd.exe', $daemonAsset), @('laneway-compat.exe', $compatAsset))) {
        $installed = Get-FileHash -LiteralPath (Join-Path $bin $item[0]) -Algorithm SHA256
        $expected = Get-FileHash -LiteralPath $item[1].FullName -Algorithm SHA256
        if ($installed.Hash -ne $expected.Hash) { throw "Installed $($item[0]) has the wrong digest." }
    }
}

function Assert-NativeCompanion {
    $PSNativeCommandUseErrorActionPreference = $false
    $installed = Join-Path $bin 'laneway-compat.exe'
    $metadata = (& go version -m $installed 2>&1) -join "`n"
    if ($metadata -notmatch 'not a Go executable') {
        throw "Installed Windows compatibility helper contains Go build metadata: $metadata"
    }
    $helpText = (& $installed _network-helper --help 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $helpText -notmatch 'Usage of _network-helper:') {
        throw "Installed Windows compatibility helper did not show offline help: $helpText"
    }
    $unsupported = (& $installed _network-helper --control-fd=0 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 1 -or $unsupported -ne 'laneway: platform: operation unsupported on this operating system') {
        throw "Installed Windows compatibility helper did not reject privileged networking: $unsupported"
    }
    $refusal = (& $installed configure --help 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 1 -or $refusal -ne 'laneway: use the laneway command for client and server operations') {
        throw "Installed Windows compatibility helper exposes a public command: $refusal"
    }
}

try {
    [System.IO.Directory]::CreateDirectory($state) | Out-Null
    [System.IO.Directory]::CreateDirectory($bin) | Out-Null
    Set-Content -LiteralPath (Join-Path $state 'state-canary.txt') -Value 'preserve this state'
    # The fixture supplies locally built assets and a verifier stub. Production
    # always authenticates the tagged manifest with cosign.
    Set-Content -LiteralPath (Join-Path $work 'cosign.cmd') -Value @'
@echo off
if not "%~1"=="verify-blob" exit /b 2
if not "%~2"=="--bundle" exit /b 3
findstr /x fixture-signature "%~3" >nul
exit /b %ERRORLEVEL%
'@
    $env:LOCALAPPDATA = $work
    $env:Path = "$work;$path"
    $stage = New-Stage
    & $shell -NoProfile -NonInteractive -File $installer -Version v1.2.3 -VerifiedStage $stage
    if ($LASTEXITCODE -ne 0) { throw 'Initial install failed.' }
    Assert-CompleteInstall
    $version = & (Join-Path $bin 'laneway.exe') version
    if ($LASTEXITCODE -ne 0 -or !$version) { throw 'Installed CLI did not report its version.' }
    $compatVersion = & (Join-Path $bin 'laneway-compat.exe') version
    if ($LASTEXITCODE -ne 0 -or $compatVersion -ne $version) { throw 'Installed compatibility helper has a different version.' }
    Assert-NativeCompanion
    $daemonVersion = & (Join-Path $bin 'lanewayd.exe') --version
    if ($LASTEXITCODE -ne 0 -or $daemonVersion -ne "lanewayd $version") { throw 'Installed daemon has a different version.' }

    $stage = New-Stage
    $bundle = Join-Path $stage 'checksums.sigstore.json'
    Set-Content -LiteralPath $bundle -Value 'invalid'
    & $shell -NoProfile -NonInteractive -File $installer -Version v1.2.3 -VerifiedStage $stage
    if ($LASTEXITCODE -eq 0) { throw 'Installer accepted an unverified manifest.' }
    Assert-CompleteInstall
    Set-Content -LiteralPath $bundle -Value 'fixture-signature'
    $exclusive = [System.IO.File]::Open((Join-Path $bin 'laneway.exe'), 'Open', 'Read', 'Read')
    try {
        & $shell -NoProfile -NonInteractive -File $installer -Version v1.2.3 -VerifiedStage $stage
        if ($LASTEXITCODE -ne 75) { throw 'Locked CLI did not report deferred installation.' }
        if (!(Test-Path -LiteralPath (Join-Path $stage $daemonAsset.Name))) {
            throw 'Installation consumed the staged daemon before detecting the locked CLI.'
        }
        Assert-CompleteInstall
    } finally {
        $exclusive.Dispose()
    }

    # Model an interrupted update after backing up and publishing the daemon.
    $backup = Join-Path $bin '.laneway-backup'
    [System.IO.Directory]::CreateDirectory($backup) | Out-Null
    $daemonTarget = Join-Path $bin 'lanewayd.exe'
    [System.IO.File]::Move($daemonTarget, (Join-Path $backup 'lanewayd.exe'))
    Set-Content -LiteralPath $daemonTarget -Value 'incomplete update'
    $exclusive = [System.IO.File]::Open((Join-Path $bin 'laneway.exe'), 'Open', 'Read', 'Read')
    try {
        & $shell -NoProfile -NonInteractive -File $installer -Version v1.2.3 -VerifiedStage $stage
        if ($LASTEXITCODE -ne 75) { throw 'Installer could not recover the interrupted transaction.' }
        Assert-CompleteInstall
    } finally {
        $exclusive.Dispose()
    }

    $parent = Start-Process -FilePath $shell -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 3' -PassThru
    & $shell -NoProfile -NonInteractive -File $installer -Version v1.2.3 -VerifiedStage $stage -WaitForProcessId $parent.Id
    if ($LASTEXITCODE -ne 0 -or !$parent.HasExited) { throw 'Installation after the parent exited failed.' }
    if (Test-Path -LiteralPath $stage) { throw 'Deferred update did not clean the staging directory.' }
    Assert-CompleteInstall
    if ((Get-Content -LiteralPath (Join-Path $state 'state-canary.txt')) -ne 'preserve this state') {
        throw 'The installer changed the state directory.'
    }
} finally {
    $env:LOCALAPPDATA = $root
    $env:Path = $path
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
