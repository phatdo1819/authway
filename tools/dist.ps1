# Builds the releases: dist\<exe name>-<version>-<x64|arm64>.msi, the MSI package with the exe, wireguard.dll
# and the licenses. Needs WiX Toolset 3.14 (candle and light), and tools\fetch-wireguard.ps1 run once before.
param(
    [string[]]$Arch = @('x64', 'arm64'),
    # the bin folder of WiX Toolset 3.14: its setup sets %WIX%
    [string]$Wix = $(if ($env:WIX) { Join-Path $env:WIX 'bin' } else { '' })
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$builds = @{
    x64 = @{ Target = 'x86_64-pc-windows-msvc'; WireGuard = 'amd64' }
    arm64 = @{ Target = 'aarch64-pc-windows-msvc'; WireGuard = 'arm64' }
}
$candle = Join-Path $Wix 'candle.exe'
$light = Join-Path $Wix 'light.exe'
if (-not $Wix -or -not (Test-Path $candle) -or -not (Test-Path $light)) {
    throw 'candle.exe and light.exe are missing: install WiX Toolset 3.14, or pass -Wix <its bin folder>'
}
$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
# the names of the app, as the exe has them
$names = @{}
foreach ($match in (Select-String -Path (Join-Path $root 'src\product.rs') -Pattern '^pub const (\w+): &str = "(.*)";').Matches) {
    $names[$match.Groups[1].Value] = $match.Groups[2].Value
}
New-Item -ItemType Directory -Force (Join-Path $root 'dist') | Out-Null
foreach ($name in $Arch) {
    $build = $builds[$name]
    $wireguard = Join-Path $root "wireguard\$($build.WireGuard)"
    if (-not (Test-Path "$wireguard\wireguard.dll")) {
        throw "$wireguard\wireguard.dll is missing: run tools\fetch-wireguard.ps1"
    }
    # through cmd: Windows PowerShell takes the progress of cargo on stderr for errors
    cmd /c "cargo build --release --target $($build.Target) --manifest-path `"$(Join-Path $root 'Cargo.toml')`" 2>&1"
    if ($LASTEXITCODE -ne 0) {
        throw "the build for $($build.Target) failed"
    }
    $work = Join-Path $root "target\msi\$name"
    New-Item -ItemType Directory -Force $work | Out-Null
    $msi = Join-Path $root "dist\$([IO.Path]::GetFileNameWithoutExtension($names.EXE_NAME))-$version-$name.msi"
    & $candle -nologo -arch $name -ext WixUtilExtension -out "$work\" `
        "-dProduct=$($names.PRODUCT)" "-dManufacturer=$($names.MANUFACTURER)" "-dUpgradeCode=$($names.UPGRADE_CODE)" `
        "-dExeName=$($names.EXE_NAME)" "-dServiceName=$($names.SERVICE_NAME)" `
        "-dServiceDisplayName=$($names.SERVICE_DISPLAY_NAME)" "-dServiceDescription=$($names.SERVICE_DESCRIPTION)" `
        "-dVersion=$version" "-dRoot=$root" "-dExeSource=$root\target\$($build.Target)\release\$($names.EXE_NAME)" `
        "-dWireGuardDir=$wireguard" "-dWireGuardLicense=$root\wireguard\wireguard-LICENSE.txt" `
        (Join-Path $root 'installer\package.wxs')
    if ($LASTEXITCODE -ne 0) {
        throw "candle failed for $name"
    }
    # ICE61: a package of the same version replaces the installed one, on purpose. ICE43 and ICE57: they take the
    # Start menu for the one of the user, while this package is for the whole computer and uses the common one.
    & $light -nologo -ext WixUIExtension -ext WixUtilExtension -cultures:en-us -sice:ICE61 -sice:ICE43 -sice:ICE57 `
        -spdb -out $msi `
        "$work\package.wixobj"
    if ($LASTEXITCODE -ne 0) {
        throw "light failed for $name"
    }
    "{0}: {1:N0} KB, SHA-256 {2}" -f $msi, ((Get-Item $msi).Length / 1KB), (Get-FileHash $msi -Algorithm SHA256).Hash
}
