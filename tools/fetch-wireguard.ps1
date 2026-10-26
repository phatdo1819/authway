# Downloads wireguard.dll of WireGuardNT into wireguard\<arch>\, for dist.ps1: the zip must have the expected
# SHA-256 and each dll the signature of WireGuard LLC. The dlls are shipped as they are, never changed.
param(
    [string]$Version = '1.1',
    [string]$Sha256 = 'dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path ([IO.Path]::GetTempPath()) "wireguard-nt-$Version-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
try {
    $zip = Join-Path $work 'wireguard-nt.zip'
    Invoke-WebRequest -UseBasicParsing "https://download.wireguard.com/wireguard-nt/wireguard-nt-$Version.zip" -OutFile $zip
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $Sha256) {
        throw "wireguard-nt-$Version.zip has the SHA-256 $hash instead of $Sha256"
    }
    Expand-Archive -Force $zip (Join-Path $work 'files')
    $files = Join-Path $work 'files\wireguard-nt'
    foreach ($arch in 'amd64', 'arm64') {
        $dll = Join-Path $files "bin\$arch\wireguard.dll"
        $signature = Get-AuthenticodeSignature $dll
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=WireGuard LLC,') {
            throw "the $arch wireguard.dll isn't signed by WireGuard LLC"
        }
        $target = Join-Path $root "wireguard\$arch"
        New-Item -ItemType Directory -Force $target | Out-Null
        Copy-Item $dll $target
        "{0}: {1}" -f $arch, (Get-Item $dll).VersionInfo.FileVersion
    }
    # its license goes with it
    Copy-Item (Join-Path $files 'LICENSE.txt') (Join-Path $root 'wireguard\wireguard-LICENSE.txt')
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
