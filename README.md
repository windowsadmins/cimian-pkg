# cimipkg - Cimian Package Builder

A standalone tool for building `.msi`, `.pkg`, and `.nupkg` packages for [Cimian](https://github.com/windowsadmins/cimian) software deployment.

## Overview

`cimipkg` reads a `build-info.yaml` file describing your package and produces signed, versioned packages containing payload files and lifecycle scripts. The default output format is `.msi` (Windows Installer), built natively via the DTF (WixToolset.Dtf.WindowsInstaller) API — no WiX Toolset or msiexec required.

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| `.msi` | *(default)* | Native Windows Installer package via DTF. Embeds payload in CAB, scripts as custom actions, full build-info.yaml round-trip via `CIMIAN_PKG_BUILD_INFO` property. |
| `.nupkg` | `--nupkg` | Chocolatey-compatible NuGet package. Add `--intunewin` to also generate `.intunewin`. |
| `.pkg` | `--pkg` | ZIP-based package for sbin-installer. |

## Installation

### As part of CimianTools

`cimipkg` is included in the [CimianTools](https://github.com/windowsadmins/cimian) build system and ships alongside all other Cimian binaries.

### Standalone build

```bash
dotnet publish -c Release -r win-x64
dotnet publish -c Release -r win-arm64
```

## Usage

```bash
# Build an MSI (default) from a project directory
cimipkg <project-directory>

# Build with verbose output
cimipkg --verbose <project-directory>

# Build .pkg format instead
cimipkg --pkg <project-directory>

# Build .nupkg format
cimipkg --nupkg <project-directory>

# Build .nupkg + .intunewin
cimipkg --nupkg --intunewin <project-directory>

# Create a new project scaffold
cimipkg --create <directory-name>

# Sign with a specific certificate
cimipkg --sign-cert "My Certificate Name" <project-directory>
cimipkg --sign-thumbprint ABCDEF1234 <project-directory>

# Re-sign an existing .pkg
cimipkg --resign <path-to.pkg> --resign-cert "My Certificate Name"

# Build without the post-build cimiimport prompt (CI/CD)
cimipkg --skip-import <project-directory>
```

### Post-build import prompt

After a successful build, `cimipkg` asks whether to run `cimiimport` on the
freshly-built package so you can push it into a Cimian repo without a second
command. The prompt has three fast-paths so it never blocks automation:

- `--skip-import` — suppresses the prompt entirely.
- Non-interactive stdin (CI runners, piped input, IDE run-configs) — detected
  via `Console.IsInputRedirected` and skipped silently.
- 60-second timeout — if nobody answers, the default is **no**.

When you accept, `cimipkg` launches `cimiimport <pkg-path>` with stdio
inherited from the parent terminal so its own interactive metadata prompts
(category, description, display name, etc.) work normally. `cimiimport` is
resolved first from the directory next to `cimipkg`, then from `PATH`.

## Project Structure

The same project structure works for all output formats:

```
my-package/
├── build-info.yaml    # Package metadata (required)
├── payload/           # Files to install (optional)
└── scripts/           # Lifecycle scripts (optional)
    ├── preinstall.ps1
    ├── postinstall.ps1
    ├── preuninstall.ps1
    └── postuninstall.ps1
```

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
signing_certificate: My Certificate Name
```

### MSI-Specific Fields

```yaml
# Optional: explicit UpgradeCode (otherwise derived deterministically from identifier)
upgrade_code: "{GUID}"

# Optional: additional MSI properties
msi_properties:
  CUSTOM_PROP: "value"
```

### Dynamic Versioning

Use placeholders in the version field:

- `${TIMESTAMP}` — `YYYY.MM.DD.HHMM`
- `${DATE}` — `YYYY.MM.DD`
- `${DATETIME}` — `YYYY.MM.DD.HHMMSS`
- `${version}` — reference the resolved version in the name field

### MSI Version Handling

MSI requires `major.minor.build` format (each field has limits: 0-255, 0-255, 0-65535). Date-based versions are automatically converted: `2026.04.05.1423` becomes `26.4.51423`. The original version is preserved in the `CIMIAN_FULL_VERSION` MSI property.

## How MSI Builds Work

When building `.msi`, cimipkg:

1. Creates MSI tables (Property, Directory, Component, File, Media, Feature, etc.) via DTF
2. Embeds payload files in a compressed CAB archive
3. Converts PowerShell scripts to silent VBScript custom actions
4. Stores the full `build-info.yaml` in the `CIMIAN_PKG_BUILD_INFO` MSI property for metadata round-trip
5. Generates a deterministic `UpgradeCode` from the product identifier (stable across versions)
6. Signs the MSI if a signing certificate is configured

The resulting MSI is a standard Windows Installer package that can be installed by `sbin-installer`, `msiexec`, or any MDM system.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
