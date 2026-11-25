#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Download')]
param(
    [Parameter(ParameterSetName = 'Download', Position = 0)]
    [Parameter(Mandatory = $true, ParameterSetName = 'VerifiedUpdate')]
    [ValidatePattern('\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z')]
    [string] $Version,
    [Parameter(Mandatory = $true, ParameterSetName = 'VerifiedUpdate')]
    [string] $VerifiedStage,
    [Parameter(ParameterSetName = 'VerifiedUpdate')]
    [ValidateRange(1, 2147483647)]
    [int] $WaitForProcessId,
    [Parameter(ParameterSetName = 'VerifiedUpdate')]
    [ValidateRange(1, 2147483647)]
    [int] $WaitForFrontendProcessId
)

$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'Use install-node.sh on Linux and macOS.' }
if (![System.IO.Path]::IsPathFullyQualified($env:LOCALAPPDATA)) { throw 'LOCALAPPDATA must be an absolute path.' }
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    X64 { 'amd64' }
    Arm64 { 'arm64' }
    default { throw 'Supported architectures are amd64 and arm64.' }
}
$root = Join-Path $env:LOCALAPPDATA 'Laneway'
$binDir = Join-Path $root 'bin'
$rollback = Join-Path $binDir '.laneway-backup'
$committed = Join-Path $binDir '.laneway-committed'
$executables = [ordered]@{
    'lanewayd.exe' = "lanewayd_windows_${arch}.exe"
    'laneway-compat.exe' = "laneway-compat_windows_${arch}.exe"
    'laneway.exe'  = "laneway-native_windows_${arch}.exe"
}
$exitRetryAfterCLI = 75
$repo = 'Doout/laneway'

function Resolve-LatestTag {
    $latest = curl.exe --disable --fail --silent --show-error --location --max-redirs 4 `
        --proto '=https' --proto-redir '=https' --max-time 120 --output NUL --write-out '%{url_effective}' `
        "https://github.com/$repo/releases/latest"
    $pattern = '\Ahttps://github\.com/' + [regex]::Escape($repo) + '/releases/tag/(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\z'
    if ($LASTEXITCODE -ne 0 -or $latest -notmatch $pattern) {
        throw 'Could not resolve the immutable latest stable release tag.'
    }
    return $Matches[1]
}

if (!$Version) { $Version = Resolve-LatestTag }

function Assert-PathType([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))) {
        throw "Unexpected file type for $Path."
    }
}

function Remove-Backups {
    if ([System.IO.Directory]::Exists($rollback)) {
        [System.IO.Directory]::Delete($rollback, $true)
    }
    [System.IO.File]::Delete($committed)
}

function Repair-Install {
    Assert-PathType $rollback $true
    Assert-PathType $committed $false
    if ([System.IO.File]::Exists($committed)) {
        Remove-Backups
        return
    }
    if (![System.IO.Directory]::Exists($rollback)) { return }
    foreach ($name in $executables.Keys) {
        $target = Join-Path $binDir $name
        $backup = Join-Path $rollback $name
        $absent = Join-Path $rollback "$name.absent"
        Assert-PathType $target $false
        Assert-PathType $backup $false
        Assert-PathType $absent $false
        if ([System.IO.File]::Exists($backup)) {
            [System.IO.File]::Move($backup, $target, $true)
        } elseif ([System.IO.File]::Exists($absent)) {
            [System.IO.File]::Delete($target)
        }
    }
    Remove-Backups
}

function Install-Executables([string] $Stage) {
    $lockPath = Join-Path $binDir '.laneway-install.lock'
    Assert-PathType $lockPath $false
    try {
        $lock = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    } catch {
        throw "Could not lock $binDir for installation. Wait for other Laneway installs to finish. $_"
    }
    try {
        Repair-Install
        foreach ($name in $executables.Keys) { Assert-PathType (Join-Path $binDir $name) $false }
        [System.IO.Directory]::CreateDirectory($rollback) | Out-Null
        $renamingLauncher = $false
        try {
            foreach ($name in $executables.Keys) {
                $target = Join-Path $binDir $name
                if (![System.IO.File]::Exists($target)) {
                    [System.IO.File]::WriteAllText((Join-Path $rollback "$name.absent"), '')
                } else {
                    $renamingLauncher = $name -ne 'lanewayd.exe'
                    [System.IO.File]::Move($target, (Join-Path $rollback $name))
                    $renamingLauncher = $false
                }
            }
            foreach ($name in $executables.Keys) {
                [System.IO.File]::Move((Join-Path $Stage $executables[$name]), (Join-Path $binDir $name))
            }
            [System.IO.File]::WriteAllText($committed, '')
        } catch {
            $failure = $_
            try {
                Repair-Install
            } catch {
                throw "Installation failed. Recovery files remain at $rollback. Close Laneway processes and rerun the installer. $_"
            }
            if ($renamingLauncher -and $VerifiedStage -and !$WaitForProcessId) {
                return $exitRetryAfterCLI
            }
            throw "Installation failed and previous executables were restored. Close running Laneway processes and retry. $failure"
        }
        try {
            Remove-Backups
        } catch {
            Write-Warning "The upgrade succeeded. Close older Laneway processes before the next install to release their backups at $rollback."
        }
        Write-Host "Installed Laneway $Version at $binDir"
        return 0
    } finally {
        $lock.Dispose()
    }
}

function Get-SignedChecksums([string] $Stage, [bool] $Download, [bool] $CompleteLegacyStage = $false) {
    $baseUrl = "https://github.com/$repo/releases/download/$Version"
    $cosign = Get-Command cosign -CommandType Application -ErrorAction SilentlyContinue
    if (!$cosign) { throw 'cosign is required to authenticate the signed release.' }
    foreach ($file in @('checksums.txt', 'checksums.sigstore.json')) {
        $path = Join-Path $Stage $file
        Assert-PathType $path $false
        if ($Download) {
            curl.exe --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' `
                --max-redirs 4 --max-time 120 --max-filesize 1048576 "$baseUrl/$file" --output $path
            if ($LASTEXITCODE -ne 0) { throw "Download failed for $file." }
        }
        if ((Get-Item -LiteralPath $path -Force).Length -gt 1048576) { throw "Oversized $file." }
    }
    $manifest = Join-Path $Stage 'checksums.txt'
    $bundle = Join-Path $Stage 'checksums.sigstore.json'
    Get-ChildItem Env: | Where-Object Name -Match '^(COSIGN|SIGSTORE|TUF)_' | ForEach-Object {
        [System.Environment]::SetEnvironmentVariable($_.Name, $null)
    }
    & $cosign.Source verify-blob --bundle $bundle `
        --certificate-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$Version" `
        --certificate-oidc-issuer https://token.actions.githubusercontent.com $manifest | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Release signature verification failed.' }
    $hashes = @{}
    foreach ($asset in $executables.Values) {
        $matchesForAsset = @(Select-String -LiteralPath $manifest -CaseSensitive -Pattern (
            '\A([a-f0-9]{64})  ' + [regex]::Escape($asset) + '\z'))
        if ($matchesForAsset.Count -ne 1) { throw "Missing or duplicate signed checksum for $asset." }
        $hashes[$asset] = $matchesForAsset[0].Matches[0].Groups[1].Value
        $candidate = Join-Path $Stage $asset
        Assert-PathType $candidate $false
        if ($Download -or ($CompleteLegacyStage -and ![System.IO.File]::Exists($candidate))) {
            curl.exe --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' `
                --max-redirs 4 --max-time 300 --max-filesize 134217728 "$baseUrl/$asset" --output $candidate
            if ($LASTEXITCODE -ne 0) { throw "Download failed for $asset." }
        }
    }
    return $hashes
}

Assert-PathType $root $true
Assert-PathType $binDir $true
$cleanup = $false
try {
    if ($VerifiedStage) {
        $stage = [System.IO.Path]::GetFullPath($VerifiedStage)
        if ((Split-Path -Parent $stage) -ine $binDir -or (Split-Path -Leaf $stage) -notlike '.laneway-stage-*') {
            throw 'Invalid verified update staging directory.'
        }
        Assert-PathType $stage $true
        $cleanup = $WaitForProcessId -ne 0
        foreach ($processId in @($WaitForProcessId, $WaitForFrontendProcessId)) {
            if (!$processId) { continue }
            $parent = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($parent -and !$parent.WaitForExit(45000)) { throw 'Timed out waiting for the Laneway CLI to exit.' }
        }
        # The previous updater staged a legacy Go CLI and lanewayd. It already
        # verified this script; complete the same tagged release's signed set.
        $legacyAsset = Join-Path $stage "laneway_windows_${arch}.exe"
        Assert-PathType $legacyAsset $false
        $hashes = Get-SignedChecksums $stage $false ([System.IO.File]::Exists($legacyAsset))
    } else {
        $stage = Join-Path $binDir ('.laneway-stage-' + [guid]::NewGuid().ToString('N'))
        [System.IO.Directory]::CreateDirectory($stage) | Out-Null
        $cleanup = $true
        $hashes = Get-SignedChecksums $stage $true
    }
    foreach ($asset in $executables.Values) {
        $binary = Join-Path $stage $asset
        Assert-PathType $binary $false
        if ((Get-Item -LiteralPath $binary -Force).Length -gt 134217728) { throw "Oversized $asset." }
        if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ine $hashes[$asset]) {
            throw "Executable checksum verification failed for $asset."
        }
    }
    exit (Install-Executables $stage)
} finally {
    if ($cleanup) { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
}
