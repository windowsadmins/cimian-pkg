param([switch]$ShutdownWhenDone, [switch]$LegacyOnly)
$ErrorActionPreference = 'Stop'
if ($env:USERNAME -ne 'WDAGUtilityAccount') { throw 'Run only inside Windows Sandbox.' }
$output = 'C:\ValidationOutput'
$checks = [Collections.Generic.List[object]]::new()
$installDir = 'C:\Program Files\Bob''s $Widget`test [v2]'
$sourceDir = 'C:\CimipkgValidation\Bob''s $Packages [v2]'
$events = 'C:\ProgramData\CimipkgValidation\events.jsonl'
function Check($name, $condition) {
    $checks.Add([pscustomobject]@{name=$name; passed=[bool]$condition})
    $checks | ConvertTo-Json -Depth 4 | Set-Content "$output\checks.json"
    if (-not $condition) { throw "Failed: $name" }
}
function Install($file, $name, $verb='/i', $extra='') {
    $msi = if ($file.StartsWith('{')) { $file } else { Join-Path $sourceDir $file }
    $p = Start-Process msiexec.exe -ArgumentList "$verb `"$msi`" /qn /norestart $extra /L*v! `"$output\$name.log`"" -PassThru
    if (-not $p.WaitForExit(180000)) {
        Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name | ConvertTo-Json | Set-Content "$output\$name-processes.json"
        Stop-Process -Id $p.Id -Force
        throw "MSI operation timed out: $name"
    }
    return $p.ExitCode
}
function Events { if (Test-Path $events) { Get-Content $events | ForEach-Object { $_ | ConvertFrom-Json } } }
function ProductCount {
    return @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName -eq 'Cimipkg Runtime Probe').Count
}
function VbsExit {
    $p = Start-Process cscript.exe -ArgumentList '//nologo //E:VBScript C:\CimipkgValidation\engine.vbs' -Wait -PassThru -RedirectStandardOutput "$output\vbs-probe.txt" -RedirectStandardError "$output\vbs-probe-error.txt"
    return $p.ExitCode
}
try {
    foreach ($store in 'Root', 'CA') {
        foreach ($cert in Get-ChildItem "C:\ValidationInput\trust-$store-*.cer") {
            Import-Certificate -FilePath $cert.FullName -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
        }
    }
    New-Item $sourceDir -ItemType Directory -Force | Out-Null
    Copy-Item 'C:\ValidationInput\*.msi' $sourceDir
    Set-Content 'C:\CimipkgValidation\engine.vbs' 'WScript.Echo "VBScript available"'
    Check 'Fresh image has no VBScript DLL or usable engine' ((-not (Test-Path "$env:WINDIR\System32\vbscript.dll")) -and (VbsExit) -ne 0)
    if ($LegacyOnly -and -not (Test-Path 'C:\ValidationInput\probe-legacy.msi')) { throw 'LegacyOnly requires a legacy MSI.' }
    if (-not $LegacyOnly) {
        Check 'Fresh install with literal source and destination paths' ((Install 'probe-1.msi' '01-install') -eq 0)
        Check 'Payload installed' ((Get-Content -LiteralPath "$installDir\marker.txt" -Raw).Trim() -eq '1.0.0')
        Check 'Exactly one registered product' ((ProductCount) -eq 1)
        $initial = @(Events)
        Check 'Preinstall and postinstall ran with exact environment' ($initial.Count -eq 2 -and @($initial | Where-Object { $_.installDir.TrimEnd('\') -ne $installDir -or $_.payloadRoot.TrimEnd('\') -ne $installDir -or $_.phase -ne 'install' -or $_.version -ne '1.0.0' -or $_.psVersion -notlike '5.1*' }).Count -eq 0)
        Check 'Deferred postinstall runs as LocalSystem' (@($initial | Where-Object { $_.action -eq 'postinstall' -and $_.sid -eq 'S-1-5-18' }).Count -eq 1)
        Check 'Sidecar output captured' ((Test-Path 'C:\ProgramData\ManagedInstalls\logs\packages\Cimipkg Runtime Probe\postinstall.log') -and (Get-Content 'C:\ProgramData\ManagedInstalls\logs\packages\Cimipkg Runtime Probe\postinstall.log' -Raw) -match 'probe postinstall')
        Check 'Same-version reinstall' ((Install 'probe-1.msi' '02-reinstall') -eq 0)
        Check 'Repair' ((Install 'probe-1.msi' '03-repair' '/fa') -eq 0)
        Check 'Upgrade' ((Install 'probe-2.msi' '04-upgrade') -eq 0)
        Check 'Upgrade replaces payload and preserves one registration' (((Get-Content -LiteralPath "$installDir\marker.txt" -Raw).Trim() -eq '1.1.0') -and (ProductCount) -eq 1)
        Check 'Old uninstall does not run during upgrade' (@(Events | Where-Object action -eq 'uninstall').Count -eq 0)
        $productCode = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object DisplayName -eq 'Cimipkg Runtime Probe').PSChildName
        Move-Item -LiteralPath "$sourceDir\probe-2.msi" -Destination "$sourceDir\probe-2.removed"
        Check 'Uninstall uses cached MSI after source removal' ((Install $productCode '05-uninstall' '/x') -eq 0)
        Check 'Uninstall removes payload and registration' ((-not (Test-Path -LiteralPath "$installDir\marker.txt")) -and (ProductCount) -eq 0)
        Check 'Uninstall script ran' (@(Events | Where-Object { $_.action -eq 'uninstall' -and $_.phase -eq 'uninstall' }).Count -eq 1)
        Check 'Failing postinstall returns 1603' ((Install 'probe-fail.msi' '06-failure') -eq 1603)
        Check 'Failed installation rolls back' ((-not (Test-Path -LiteralPath "$installDir\marker.txt")) -and (ProductCount) -eq 0)
        Check 'Temporary scripts cleaned up' (@(Get-ChildItem "$env:TEMP\cimian-*.ps1" -ErrorAction SilentlyContinue).Count -eq 0)
    }
    if (Test-Path 'C:\ValidationInput\probe-legacy.msi') {
        Check 'Legacy package fails without VBScript' ((Install 'probe-legacy.msi' '07-legacy-absent') -eq 1603)
        Check 'Legacy failure identifies missing script engine' ((Get-Content "$output\07-legacy-absent.log" -Raw) -match '2738')
        foreach ($arch in 'System32', 'SysWOW64') {
            Copy-Item "C:\ValidationInput\$arch-vbscript.dll" "$env:WINDIR\$arch\vbscript.dll" -Force
        }
        foreach ($file in Get-ChildItem 'C:\ValidationInput\*.reg') {
            & reg.exe import $file.FullName | Out-Null
            if ($LASTEXITCODE) { throw 'Could not register the guest VBScript fixture.' }
        }
        Check 'VBScript fixture is usable' ((VbsExit) -eq 0)
        Check 'Legacy package installs with VBScript' ((Install 'probe-legacy.msi' '08-legacy-present') -eq 0)
        Stop-Service msiserver -Force -ErrorAction SilentlyContinue
        Get-Process msiexec -ErrorAction SilentlyContinue | Stop-Process -Force
        foreach ($prefix in 'SOFTWARE\Classes\CLSID', 'SOFTWARE\Classes\WOW6432Node\CLSID') {
            foreach ($clsid in 'B54F3741', 'B54F3742', 'B54F3743') {
                & reg.exe delete "HKLM\$prefix\{$clsid-5B07-11cf-A4B0-00AA004A55E8}" /f | Out-Null
                if ($LASTEXITCODE) { throw 'Could not remove the guest VBScript fixture registration.' }
            }
        }
        foreach ($name in 'VBScript', 'VBScript.Encode') {
            & reg.exe delete "HKLM\SOFTWARE\Classes\$name" /f | Out-Null
            if ($LASTEXITCODE) { throw 'Could not remove the guest VBScript ProgID fixture.' }
        }
        foreach ($arch in 'System32', 'SysWOW64') {
            Remove-Item "$env:WINDIR\$arch\vbscript.dll" -Force
        }
        Check 'VBScript is absent again after legacy installation' ((-not (Test-Path "$env:WINDIR\System32\vbscript.dll")) -and (-not (Test-Path "$env:WINDIR\SysWOW64\vbscript.dll")) -and (VbsExit) -ne 0)
        Check 'Legacy standalone uninstall fails without VBScript' ((Install 'probe-legacy.msi' '09-legacy-uninstall-absent' '/x') -eq 1603)
        Check 'Legacy uninstall identifies missing script engine' ((Get-Content "$output\09-legacy-uninstall-absent.log" -Raw) -match '2738')
        Check 'Upgrade from legacy installed before VBScript removal' ((Install 'probe-1.msi' '10-legacy-upgrade-absent') -eq 0)
        Check 'Legacy upgrade leaves one product and current payload' ((ProductCount) -eq 1 -and (Get-Content -LiteralPath "$installDir\marker.txt" -Raw).Trim() -eq '1.0.0')
        Check 'Upgraded package uninstalls without VBScript' ((Install 'probe-1.msi' '11-upgraded-uninstall' '/x') -eq 0 -and (ProductCount) -eq 0)
    }
    Copy-Item $events "$output\events.jsonl"
    @{passed=$true;checks=$checks.Count;os=[Environment]::OSVersion.Version.ToString()} | ConvertTo-Json | Set-Content "$output\result.json"
} catch {
    @{passed=$false;checks=$checks.Count;error=$_.Exception.Message} | ConvertTo-Json | Set-Content "$output\result.json"
} finally {
    if ($ShutdownWhenDone) { shutdown.exe /s /t 10 }
}
