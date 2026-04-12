# cimipkg - Cimian Package Builder

A standalone tool for building `.msi` and `.nupkg` packages for [Cimian](https://github.com/windowsadmins/cimian) software deployment.

## Overview

`cimipkg` reads a `build-info.yaml` file describing your package and produces signed, versioned packages containing payload files and PowerShell install scripts. The default output format is `.msi` (Windows Installer), built natively via the DTF (WixToolset.Dtf.WindowsInstaller) API — no WiX Toolset or msiexec required.

### Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| `.msi` | *(default)* | Native Windows Installer package via DTF. Embeds payload in CAB, scripts as custom actions, full build-info.yaml round-trip via `CIMIAN_PKG_BUILD_INFO` property. |
| `.nupkg` | `--nupkg` | Chocolatey-compatible NuGet package. Add `--intunewin` to also generate `.intunewin`. |

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

# Build .nupkg format
cimipkg --nupkg <project-directory>

# Build .nupkg + .intunewin
cimipkg --nupkg --intunewin <project-directory>

# Create a new project scaffold
cimipkg --create <directory-name>

# Sign with a specific certificate
cimipkg --sign-cert "My Certificate Name" <project-directory>
cimipkg --sign-thumbprint ABCDEF1234 <project-directory>

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
├── .env               # Environment variables for signing + scripts (optional, gitignored)
└── scripts/           # PowerShell install/uninstall scripts (optional)
    ├── preinstall.ps1     # Runs before payload is copied
    ├── postinstall.ps1    # Runs after payload is copied
    └── uninstall.ps1      # Runs when the package is removed
```

Scripts are numbered if you need ordering (`preinstall01.ps1`, `preinstall02.ps1`, etc.)
and are combined into a single custom action per phase at build time. The `uninstall.ps1`
script runs during MSI removal (`msiexec /x`) or Chocolatey `choco uninstall`.

### How scripts map to each output format

| cimipkg script | MSI | nupkg (Chocolatey / sbin-installer) |
|---|---|---|
| `preinstall*.ps1` | Custom action before payload copy | `chocolateyBeforeModify.ps1` |
| `postinstall*.ps1` | Custom action after payload copy | `chocolateyInstall.ps1` |
| `uninstall.ps1` | Custom action on `REMOVE="ALL"` | `chocolateyUninstall.ps1` |

**Chocolatey limitation:** `chocolateyBeforeModify.ps1` only runs when an
existing package is being upgraded or uninstalled. On a fresh install,
Chocolatey does not execute it — this is a `choco` engine limitation, not a
cimipkg design choice. Packages consumed by
[sbin-installer](https://github.com/windowsadmins/sbin-installer) do not have
this limitation — sbin-installer executes `chocolateyBeforeModify.ps1`
unconditionally before every install.

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

### Placeholders

Any scalar field in `build-info.yaml` can contain `${NAME}` placeholders, which
`cimipkg` resolves in this order (highest priority first):

1. **Built-in tokens** (always win, cannot be shadowed):
   - `${TIMESTAMP}` → `YYYY.MM.DD.HHMM` (e.g. `2026.04.11.1723`)
   - `${DATE}` → `YYYY.MM.DD`
   - `${DATETIME}` → `YYYY.MM.DD.HHMMSS`
   - `${version}` → the resolved `product.version` (only in other fields — see below)
2. **`.env` file** in the project directory (auto-detected, or pass `--env <path>`)
3. **Process environment variables**
4. **Unresolved** → the literal `${NAME}` is left in place (fail-soft). The
   downstream tool (e.g. `signtool`) surfaces the real error.

`${version}` is a back-reference: inside `product.version` itself it stays
literal, but in `product.name`, `product.identifier`, and `product.description`
it expands to the already-resolved version.

#### Fields that support placeholders

- `product.version`, `product.name`, `product.identifier`, `product.description`
- `signing_certificate`, `signing_thumbprint`
- `install_location`, `install_arguments`, `uninstall_arguments`
- `upgrade_code`

#### Keeping signing details out of source control

Consumer repos often commit `build-info.yaml` publicly but need to sign with an
organization-specific certificate (so AV/EDR products trust the resulting
binaries). Reference the cert via a placeholder and keep the real value in a
gitignored `.env` or in CI environment variables:

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

The variable names are entirely your choice — `cimipkg` doesn't prescribe a
vocabulary, it just looks up whatever `${NAME}` you wrote. The convention used
in examples is `SIGNING_CERT_*` because that mirrors how `signtool` thinks
about the cert. CLI flags (`--sign-thumbprint`, `--sign-cert`) still override
anything resolved from YAML or env.

The same `.env` file is also used to inject variables into install/uninstall
scripts at build time, so one file can serve both purposes.

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
