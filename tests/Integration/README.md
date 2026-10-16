# Windows Sandbox installer validation

Build the Windows x64 package builder, then run this harness on a Windows host with Windows Sandbox enabled. If the host requires signed executables, sign the builder through your normal signing process first.

```powershell
.\tests\Integration\Invoke-VBScriptFreeSandbox.ps1 -BuilderPath .\publish\cimipkg.exe
```

The harness builds three disposable probe packages and opens a fresh Sandbox with networking and clipboard sharing disabled. It maps only the generated input folder (read-only) and the results folder (writable). It does not install packages on the host.

The guest first verifies that VBScript is unavailable. It checks fresh installation, reinstall, repair, upgrade, uninstall, sidecar output, script environment, cleanup and rollback after a failing postinstall. Source and install paths contain apostrophes, dollar signs and square brackets; the install path also contains a backtick. Installation uses Windows PowerShell 5.1 on the stock image; an unexpected runtime causes the environment check to fail.

The command prints the output directory. Wait for `result.json`; `passed` must be `true`. `checks.json`, `events.jsonl` and the verbose MSI logs preserve the evidence. The Sandbox shuts down after writing its result.

Each MSI operation has a three-minute timeout and flushes every log line. The uninstall check removes the source MSI and uninstalls by product code, exercising the cached package.

For signed package validation, pass `-SigningThumbprint` with a certificate from the current user's certificate store. The builder signs the embedded scripts and MSI files. The harness exports the public certificate chain and imports it into the guest trust stores.

```powershell
.\tests\Integration\Invoke-VBScriptFreeSandbox.ps1 -BuilderPath .\publish\cimipkg.exe -SigningThumbprint $env:SIGNING_CERT_THUMBPRINT
```

To test migration, supply a released builder that generates the old VBScript format. The host must already have VBScript installed. The harness copies the Microsoft DLLs and exports their registration as test inputs; it makes no host registration or feature changes.

```powershell
.\tests\Integration\Invoke-VBScriptFreeSandbox.ps1 -BuilderPath .\publish\cimipkg.exe -LegacyBuilderPath .\baseline\cimipkg.exe
```

The guest proves that the old package fails with error 2738, registers the copied engine only inside the Sandbox and installs the old package. It then stops Windows Installer, removes the copied DLLs and registrations, and verifies that the engine and old standalone uninstall fail again. Finally it upgrades to the new package and uninstalls it without VBScript. This tests an isolated engine fixture rather than removal of the Windows Feature on Demand itself.

Add `-LegacyOnly` to run just the migration phase in a new Sandbox. This requires `-LegacyBuilderPath` and preserves separate results from the new-format lifecycle checks.

This harness does not establish arm64 execution, Intune delivery or a standard user's interactive elevation flow.
