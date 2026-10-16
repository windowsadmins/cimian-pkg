param(
    [Parameter(Mandatory)][string]$BuilderPath,
    [string]$LegacyBuilderPath,
    [string]$SigningThumbprint,
    [switch]$LegacyOnly,
    [string]$RunDirectory = (Join-Path $env:TEMP ('cimipkg-sandbox-' + [guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
if ($LegacyOnly -and -not $LegacyBuilderPath) { throw 'LegacyOnly requires LegacyBuilderPath.' }
$builder = (Resolve-Path -LiteralPath $BuilderPath).ProviderPath
if (Test-Path -LiteralPath $RunDirectory) { throw 'Use a new run directory to avoid stale results.' }
Get-Command WindowsSandbox.exe -ErrorAction Stop | Out-Null
$inputDir = Join-Path $RunDirectory 'input'
$outputDir = Join-Path $RunDirectory 'output'
New-Item $inputDir, $outputDir -ItemType Directory -Force | Out-Null
$installDir = 'C:\Program Files\Bob''s $Widget`test [v2]'
foreach ($item in @(
    @{name='probe-1'; version='1.0.0'},
    @{name='probe-2'; version='1.1.0'},
    @{name='probe-fail'; version='1.2.0'}
)) {
    $project = Join-Path $RunDirectory $item.name
    New-Item "$project\payload", "$project\scripts" -ItemType Directory -Force | Out-Null
    @"
product:
  name: Cimipkg Runtime Probe
  version: $($item.version)
  developer: WindowsAdmins
  identifier: org.windowsadmins.cimipkg.runtime-probe
install_location: $($installDir | ConvertTo-Json -Compress)
postinstall_action: none
signing_thumbprint: $SigningThumbprint
"@ | Set-Content "$project\build-info.yaml" -Encoding utf8
    $item.version | Set-Content "$project\payload\marker.txt"
    foreach ($action in @('preinstall', 'postinstall', 'uninstall')) {
        $script = @'
$ErrorActionPreference='Stop'
New-Item 'C:\ProgramData\CimipkgValidation' -ItemType Directory -Force | Out-Null
[ordered]@{action='@ACTION@';phase=$env:CIMIAN_PHASE;version=$env:CIMIAN_VERSION;installDir=$env:CIMIAN_INSTALLDIR;payloadRoot=$payloadRoot;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;psVersion=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json -Compress | Add-Content 'C:\ProgramData\CimipkgValidation\events.jsonl'
Write-Output 'probe @ACTION@'
'@
        if ($item.name -eq 'probe-fail' -and $action -eq 'postinstall') { $script += "`r`nexit 7" }
        $script.Replace('@ACTION@', $action) | Set-Content "$project\scripts\$action.ps1" -Encoding utf8
    }
    $p = Start-Process $builder -ArgumentList ('--skip-import "' + $project + '"') -RedirectStandardOutput "$project\build.log" -RedirectStandardError "$project\build-error.log" -PassThru
    if (-not $p.WaitForExit(300000)) {
        Stop-Process -Id $p.Id -Force
        throw "Build timed out: $($item.name)"
    }
    if ($p.ExitCode -ne 0) { throw "Build failed: $($item.name). See its build logs." }
    $msi = @(Get-ChildItem $project -Recurse -Filter '*.msi')
    if ($msi.Count -ne 1) { throw 'Expected exactly one generated MSI.' }
    Copy-Item -LiteralPath $msi[0].FullName -Destination "$inputDir\$($item.name).msi"
}
if ($LegacyBuilderPath) {
    $legacyBuilder = (Resolve-Path -LiteralPath $LegacyBuilderPath).ProviderPath
    $project = Join-Path $RunDirectory 'probe-legacy'
    New-Item "$project\payload", "$project\scripts" -ItemType Directory -Force | Out-Null
    Copy-Item "$RunDirectory\probe-1\scripts\*.ps1" "$project\scripts"
    '0.9.0' | Set-Content "$project\payload\marker.txt"
    @'
product:
  name: Cimipkg Runtime Probe
  version: 0.9.0
  developer: WindowsAdmins
  identifier: org.windowsadmins.cimipkg.runtime-probe
install_location: C:\Program Files\Cimipkg Legacy Probe
postinstall_action: none
'@ | Set-Content "$project\build-info.yaml" -Encoding utf8
    if ($SigningThumbprint) { Add-Content "$project\build-info.yaml" "signing_thumbprint: $SigningThumbprint" }
    $p = Start-Process $legacyBuilder -ArgumentList ('--skip-import "' + $project + '"') -RedirectStandardOutput "$project\build.log" -RedirectStandardError "$project\build-error.log" -PassThru
    if (-not $p.WaitForExit(300000)) {
        Stop-Process -Id $p.Id -Force
        throw 'Legacy build timed out.'
    }
    if ($p.ExitCode -ne 0) { throw 'Legacy build failed. See its build logs.' }
    $msi = @(Get-ChildItem $project -Recurse -Filter '*.msi')
    if ($msi.Count -ne 1) { throw 'Expected exactly one legacy MSI.' }
    Copy-Item -LiteralPath $msi[0].FullName -Destination "$inputDir\probe-legacy.msi"
    foreach ($arch in 'System32', 'SysWOW64') {
        Copy-Item "$env:WINDIR\$arch\vbscript.dll" "$inputDir\$arch-vbscript.dll" -Force
    }
    foreach ($prefix in 'SOFTWARE\Classes\CLSID', 'SOFTWARE\Classes\WOW6432Node\CLSID') {
        foreach ($clsid in 'B54F3741', 'B54F3742', 'B54F3743') {
            $name = ($prefix -replace '\\', '-') + '-' + $clsid + '.reg'
            & reg.exe export "HKLM\$prefix\{$clsid-5B07-11cf-A4B0-00AA004A55E8}" "$inputDir\$name" /y | Out-Null
            if ($LASTEXITCODE) { throw 'Could not export the read-only VBScript registry fixture.' }
        }
    }
    foreach ($name in 'VBScript', 'VBScript.Encode') {
        & reg.exe export "HKLM\SOFTWARE\Classes\$name" "$inputDir\progid-$name.reg" /y | Out-Null
        if ($LASTEXITCODE) { throw 'Could not export the read-only VBScript ProgID fixture.' }
    }
}
if ($SigningThumbprint) {
    $cert = Get-Item "Cert:\CurrentUser\My\$SigningThumbprint"
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        if (-not $chain.Build($cert)) { throw 'The signing certificate chain must be trusted on the build host.' }
        for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
            $store = if ($i -eq $chain.ChainElements.Count - 1) { 'Root' } else { 'CA' }
            [IO.File]::WriteAllBytes("$inputDir\trust-$store-$i.cer", $chain.ChainElements[$i].Certificate.Export('Cert'))
        }
    } finally { $chain.Dispose() }
}
Copy-Item "$PSScriptRoot\Test-VBScriptFreeSandbox.ps1" $inputDir
$inputXml = [Security.SecurityElement]::Escape($inputDir)
$outputXml = [Security.SecurityElement]::Escape($outputDir)
$legacySwitch = if ($LegacyOnly) { '-LegacyOnly' } else { '' }
@"
<Configuration>
  <Networking>Disable</Networking>
  <VGpu>Disable</VGpu>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MappedFolders>
    <MappedFolder><HostFolder>$inputXml</HostFolder><SandboxFolder>C:\ValidationInput</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>$outputXml</HostFolder><SandboxFolder>C:\ValidationOutput</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ValidationInput\Test-VBScriptFreeSandbox.ps1 -ShutdownWhenDone $legacySwitch</Command></LogonCommand>
</Configuration>
"@ | Set-Content "$RunDirectory\validation.wsb" -Encoding utf8
Start-Process WindowsSandbox.exe -ArgumentList ('"' + "$RunDirectory\validation.wsb" + '"')
Write-Output "Sandbox started. Results and MSI logs: $outputDir"
