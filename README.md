# cimipkg

A standalone Windows package builder. Define your package in a `build-info.yaml`, add payload files and PowerShell scripts, and `cimipkg` produces signed, versioned `.msi` or `.nupkg` packages — no WiX Toolset required.

Prebundled in [Cimian](https://github.com/windowsadmins/cimian) for enterprise software deployment.

## Installation

### Pre-built binaries

Download from [Releases](https://github.com/windowsadmins/cimian-pkg/releases) (x64 and arm64). Also ships with the [CimianTools](https://github.com/windowsadmins/cimian) build.

### Build from source

```bash
dotnet publish -c Release -r win-x64
dotnet publish -c Release -r win-arm64
```

## Quick Start

```bash
# Create a new project scaffold
cimipkg --create my-package

# Build an MSI (default)
cimipkg my-package

# Build with verbose output
cimipkg --verbose my-package
```

## Project Structure

```
my-package/
├── build-info.yaml    # Package metadata (required)
├── payload/           # Files to install (optional)
├── .env               # Environment variables for signing + scripts (optional, gitignored)
└── scripts/           # PowerShell install/uninstall scripts (optional)
    ├── preinstall.ps1     # Runs before payload is copied
    ├── postinstall.ps1    # Runs after payload is copied
    └── uninstall.ps1      # Runs when the package is removed
```

Scripts are numbered for ordering (`preinstall01.ps1`, `preinstall02.ps1`, etc.) and combined into a single action per phase at build time.

## build-info.yaml

```yaml
product:
  name: MyApp
  version: 2025.12.09
  developer: MyCompany
  identifier: com.mycompany.myapp
  description: My application package
install_location: C:\Program Files\MyApp
postinstall_action: none
signing_certificate: ${SIGNING_CERT_SUBJECT}
signing_thumbprint: ${SIGNING_CERT_THUMBPRINT}
```

### MSI-specific fields

```yaml
# Optional: explicit UpgradeCode (otherwise derived deterministically from identifier)
upgrade_code: "{GUID}"

# Optional: additional MSI properties
msi_properties:
  CUSTOM_PROP: "value"
```

### Placeholders

Any scalar field can contain `${NAME}` placeholders, resolved in order:

1. **Built-in tokens**: `${TIMESTAMP}` (`YYYY.MM.DD.HHMM`), `${DATE}`, `${DATETIME}`, `${version}`
2. **`.env` file** in the project directory (or pass `--env <path>`)
3. **Process environment variables**
4. **Unresolved** placeholders are left literal (fail-soft)

#### Keeping signing details out of source control

```yaml
# build-info.yaml (committed)
signing_thumbprint: ${SIGNING_CERT_THUMBPRINT}
signing_certificate: ${SIGNING_CERT_SUBJECT}
```

```sh
# .env (gitignored)
SIGNING_CERT_THUMBPRINT=1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B
SIGNING_CERT_SUBJECT=YourOrganization Enterprise Certificate
```

CLI flags (`--sign-thumbprint`, `--sign-cert`) override anything resolved from YAML or env. The same `.env` file also injects variables into install/uninstall scripts at build time.

## MSI

```bash
cimipkg <project-directory>
cimipkg --sign-cert "My Certificate" <project-directory>
```

The default output format. Builds native Windows Installer packages via the DTF (WixToolset.Dtf.WindowsInstaller) API — no WiX compiler or `msiexec` needed at build time.

### What cimipkg does

1. Creates MSI tables (Property, Directory, Component, File, Media, Feature, etc.)
2. Embeds payload files in a compressed CAB archive
3. Converts PowerShell scripts to VBScript custom actions (base64-encoded, chunked — supports scripts of any practical size)
4. **Authenticode-signs embedded scripts** if a signing certificate is configured — the temp `.ps1` written at install time already carries a valid signature, preventing EDR/AV false positives
5. Stores the full `build-info.yaml` in the `CIMIAN_PKG_BUILD_INFO` MSI property for metadata round-trip
6. Generates a deterministic `UpgradeCode` from the product identifier (stable across versions)
7. Signs the MSI with the configured certificate

### Runtime behavior

- Custom actions **auto-detect PowerShell 7** (`pwsh.exe`) at install time, falling back to PowerShell 5.1
- Scripts should stay 5.1-compatible, but `#Requires -Version 7` works when pwsh is installed
- The resulting MSI can be installed by `msiexec`, MDM systems, or [sbin-installer](https://github.com/windowsadmins/sbin-installer)

### Script mapping

| Project script | MSI custom action |
|---|---|
| `preinstall*.ps1` | Runs before payload copy |
| `postinstall*.ps1` | Runs after payload copy |
| `uninstall.ps1` | Runs on `REMOVE="ALL"` |

### Version handling

MSI requires `major.minor.build` format (0-255, 0-255, 0-65535). Date-based versions are automatically converted: `2026.04.05.1423` becomes `26.4.51423`. The original version is preserved in the `CIMIAN_FULL_VERSION` MSI property.

## nupkg

```bash
cimipkg --nupkg <project-directory>
```

Builds Chocolatey-compatible NuGet packages from the same project structure.

### Script mapping

| Project script | nupkg file |
|---|---|
| `preinstall*.ps1` | `chocolateyBeforeModify.ps1` |
| `postinstall*.ps1` | `chocolateyInstall.ps1` |
| `uninstall.ps1` | `chocolateyUninstall.ps1` |

**Chocolatey limitation:** `chocolateyBeforeModify.ps1` only runs on upgrade or uninstall — not on fresh install. This is a Chocolatey engine limitation. [sbin-installer](https://github.com/windowsadmins/sbin-installer) does not have this limitation and runs it unconditionally.

## Intune (.intunewin)

```bash
# Wrap an MSI for Intune
cimipkg --intunewin <project-directory>

# Wrap a nupkg for Intune
cimipkg --nupkg --intunewin <project-directory>
```

Generates `.intunewin` packages for Microsoft Intune deployment. Works with both `.msi` and `.nupkg` output formats. Requires `IntuneWinAppUtil.exe` on PATH.

For MSI, the `.msi` is used directly as the setup file. For nupkg, a Chocolatey wrapper `Install.ps1` is generated.

## CI/CD

The post-build `cimiimport` prompt is automatically skipped when stdin is non-interactive (CI runners, piped input, IDE run-configs). Use `--skip-import` to suppress it explicitly in other contexts.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
