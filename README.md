## cimipkg

`cimipkg` is a tool for building modern `.pkg` packages and legacy `.nupkg` packages for deploying software on Windows in a consistent, repeatable manner. It supports **sbin-installer** for .pkg packages and **Chocolatey** for .nupkg packages, with comprehensive **pre- and post-installation scripts** and **cryptographic package signing**.

This tool simplifies deployment complexities by providing YAML-based configuration, script-based actions, and **NuGet-style cryptographic signing** for package integrity verification.

> **⚠️ IMPORTANT**: Scripts must access payload files via `$env:payloadRoot` environment variable. See [Script Execution](#accessing-payload-files-in-scripts) section for details.

### Package Formats

- **`.pkg` (default)**: Modern ZIP-based packages compatible with **[sbin-installer](https://github.com/windowsadmins/sbin-installer)**
  - Cryptographic signature metadata embedded in `build-info.yaml`
  - Deterministic installations with full integrity verification
  - Direct script execution without dependency overhead
- **`.nupkg` (legacy)**: Traditional NuGet packages compatible with **Chocolatey**
  - NuGet package-level cryptographic signing
  - Full Chocolatey ecosystem compatibility
  - Use `--nupkg` flag to build this format

### Features

- **Dual Package Format Support** – Build modern `.pkg` or legacy `.nupkg` packages
- **Cryptographic Signing** – NuGet-style signature metadata for package integrity
- **Dynamic File Inclusion** – everything in `payload/` is packaged automatically
- **Script Support** – unlimited `preinstall*.ps1` and `postinstall*.ps1`, run elevated
- **Smart Copy / In-Place Install** –  
  • If `install_location` **has a value**, payload files are copied there  
  • If `install_location` **is empty**, cimipkg assumes the payload contains a
    vendor installer (embedded `setup.exe`, etc.) and runs it **in-place**
- **Post-Install Actions** – optional `logout` or `restart` after install
- **Package Signing** – signs PowerShell scripts and creates package integrity metadata
- **Automatic `readme.md`** – created only when `description` is present
- **One-Shot `.intunewin` Build** – add `-intunewin` with `--nupkg` to wrap for Microsoft Intune

### Prerequisites

#### For Development:
- **Go** (to build the `cimipkg` tool).
- **NuGet CLI** (for generating `.nupkg` packages).

#### For Deployment:
- **Chocolatey** or **Cimian** (for installing `.nupkg` packages).
- **PowerShell** (to run pre- and post-installation scripts).
- **Windows SDK** (for the `SignTool` utility).

### Installation

Clone the repository:

```shell
git clone https://github.com/rodchristiansen/cimian-pkg.git
cd cimian-pkg
```

### Usage

```bash
# Build a modern .pkg package (default)
cimipkg -v 1.2.3 [-sign] [-thumbprint XXXX]

# Build a legacy .nupkg package for Chocolatey
cimipkg -v 1.2.3 --nupkg [-sign] [-thumbprint XXXX]

# Create Intune package (requires --nupkg)
cimipkg -v 1.2.3 --nupkg -intunewin

# Build and sign with specific certificate thumbprint
cimipkg -v 1.2.3 -sign -thumbprint "A1B2C3D4E5F6789012345678901234567890ABCD"

# Build without signing
cimipkg -v 1.2.3 -nosign
```

#### Package Format Selection

- **Default behavior**: Creates `.pkg` packages for **sbin-installer**
- **Legacy mode**: Use `--nupkg` flag to create traditional `.nupkg` packages for **Chocolatey**

#### Command Line Options

- `-v 1.2.3`: The version of the package
- `--nupkg`: Build legacy .nupkg package instead of modern .pkg
- `-sign`: (Optional) Sign PowerShell scripts and create package integrity metadata
- `-thumbprint XXXX`: (Optional) Specify a certificate thumbprint for signing
- `-nosign`: (Optional) Skip signing even if certificates are available
- `-intunewin`: (Optional) Create an `.intunewin` wrapper for Microsoft Intune (requires --nupkg)

### Folder Structure for Packages

```
project/
├── payload/                   # Files/folders to be written to disk
│   └── example.txt
├── scripts/                   # Pre-/Post-install scripts
│   ├── preinstall.ps1         # Runs before files are installed
│   └── postinstall.ps1        # Runs after files are installed
└── build-info.yaml            # Metadata for package generation
```

### YAML Configuration: `build-info.yaml`

The `build-info.yaml` file contains configuration settings for the package:

```yaml
product:
  name: "Cimian"
  version: "2024.10.11"
  identifier: "com.cimiancorp.cimian"
  developer: "Cimian Corp"
  description: "This is the StartSet installer package."
install_location: "C:\Program Files\Cimian"
postinstall_action: "none"
signing_certificate: "Cimian Corp EV Certificate"
```
**Dynamic Versioning Example**: Use placeholders for automatic build-time versioning:

```yaml
product:
  name: "Cimian-${version}"          # Resolves to "Cimian-2025.12.17.1435"
  version: "${TIMESTAMP}"             # Resolves to "2025.12.17.1435"
  identifier: "com.cimiancorp.cimian"
  developer: "Cimian Corp"
install_location: "C:\Program Files\Cimian"
postinstall_action: "none"
```
Here’s the **Field Descriptions** section updated with the `description` field information directly included.

#### Field Descriptions

- **`identifier`**:  
  A unique identifier in reverse-domain style (e.g., `com.cimiancorp.cimian`). This ensures the package is correctly recognized by the system and prevents naming conflicts.

- **`version`**:  
  Supports **semantic versioning** (e.g., `1.0.0`) or **date-based versioning** (e.g., `2024.10.11`). Used to determine whether a new installation or update is required during deployments.  
  
  **Dynamic Version Placeholders**: You can use placeholders that are automatically resolved at build time:
  - `${TIMESTAMP}` → `YYYY.MM.DD.HHMM` (e.g., `2025.12.17.1435`)
  - `${DATE}` → `YYYY.MM.DD` (e.g., `2025.12.17`)
  - `${DATETIME}` → `YYYY.MM.DD.HHMMSS` (e.g., `2025.12.17.143530`)
  
  Example: `version: "${TIMESTAMP}"` will produce a version like `2025.12.17.1435`

- **`name`**:  
  The display name of the product. This name will be visible during installation and in package managers like Chocolatey.
  
  **Version Placeholder**: You can use `${version}` in the name field to include the resolved version:
  - `name: "MyPackage-${version}"` → `MyPackage-2025.12.17.1435` (when combined with `version: "${TIMESTAMP}"`)
  
  This is especially useful when combined with dynamic version placeholders to create automatically versioned package names.

- **`developer`**:  
  The organization or individual distributing the package. This helps users identify the source of the software and improves trust.

- **`description`**:  
  A brief description of the package's purpose or functionality. If provided, it will:
  - Be included in the `.nuspec` metadata.
  - Automatically generate a `readme.md` file to be packaged with the `.nupkg` for documentation purposes.
  - If the description is **absent**, no `readme.md` will be generated, and the process will proceed without errors or warnings.

- **`install_location`**:  
  The default directory where the software will be installed. This can be customized for each deployment.

- **`postinstall_action`**:  
  Specifies an optional action to take after installation:
  - `none`: No further action is taken after installation.
  - `logout`: Logs out the current user after installation completes.
  - `restart`: Restarts the system immediately after installation.

- **`signing_certificate`**:  
  Path to the `.pfx` certificate containing both the public and private keys, or the **name of a certificate** in the local certificate store. This certificate is used for **code signing** to ensure the package's authenticity and integrity.

### Usage

To create a new package:

```shell
cimipkg <project_dir>
```

This command will:
1. Validate the project structure.
2. Convert `build-info.yaml` into a `.nuspec` manifest.
3. Run `nuget pack` to generate the `.nupkg`.
4. Optionally sign the package using the specified certificate.
5. Execute the specified post-install action (logout or restart).

### Script Execution

- **Pre-Install**:  
  `scripts/preinstall.ps1` runs **before** copying files.

- **Post-Install**:  
  `scripts/postinstall.ps1` runs **after** installation (acts like Chocolatey’s `chocolateyInstall.ps1`).
#### Accessing Payload Files in Scripts

**CRITICAL**: When using **sbin-installer** to install `.pkg` packages, scripts must access payload files through the `$env:payloadRoot` environment variable:

```powershell
# REQUIRED: Get payload directory from environment variable
$payloadRoot = $env:payloadRoot

# Now you can access payload files
$setupExe = Join-Path $payloadRoot "setup.exe"
Start-Process -FilePath $setupExe -ArgumentList "/silent" -Wait
```

**Why this is needed:**
- sbin-installer extracts the `.pkg` to a temporary directory
- It sets `$env:payloadRoot` to point to the `payload/` subdirectory
- Scripts run with this environment variable available
- Without this, scripts will fail with "variable not defined" errors

**Common mistake:**
```powershell
# ❌ WRONG - $payloadRoot is undefined
$setupExe = Join-Path $payloadRoot "setup.exe"

# ✅ CORRECT - Get from environment variable first
$payloadRoot = $env:payloadRoot
$setupExe = Join-Path $payloadRoot "setup.exe"
```

**For installer-type packages** (where `install_location` is empty):
- Payload files remain in the extraction directory
- Scripts process installers directly from `$env:payloadRoot`
- Example: `Join-Path $env:payloadRoot "setup.exe"`

**For copy-type packages** (where `install_location` has a value):
- Files are copied to the specified location FIRST
- Then postinstall scripts run
- Use `$env:payloadRoot` in preinstall, regular paths in postinstall
### Package Signing with `SignTool`

If a signing certificate is provided, `cimipkg` will sign the package using Windows `SignTool`.

#### Using a .pfx Certificate

```shell
signtool sign /f "path\to\certificate.pfx" /p <password> /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "path\to\package.nupkg"
```

#### Using the Certificate Store

```shell
signtool sign /n "Cimian Corp EV Certificate" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "path\to\package.nupkg"
```

### Smart Readme Inclusion

- If the **`description`** field is provided in `build-info.yaml`, a `readme.md` will be generated and included in the package.
- If the description is **not** provided, the tool will skip the readme without errors.

### Example Commands

#### Building the `.nupkg`

```shell
.\cimipkg.exe C:\Users\rchristiansen\DevOps\Cimian\packages\StartSet
```

#### Installing with Chocolatey

```shell
choco install StartSet --source="C:\Users\rchristiansen\DevOps\Cimian\packages\StartSet\build"
```

### Handling Post-Install Actions

The `postinstall_action` key in `build-info.yaml` triggers system actions:
- **`none`**: No action.
- **`logout`**: Logs out the user.
- **`restart`**: Restarts the system immediately.

### Example Output

```
2024/10/14 13:00:00 main.go:350: Using project directory: C:\Users\rchristiansen\DevOps\Cimian\packages\StartSet
2024/10/14 13:00:00 main.go:356: Project structure verified. Proceeding with package creation...
2024/10/14 13:00:00 main.go:394: Package successfully created: StartSet.nupkg
2024/10/14 13:00:02 main.go:446: Package signed successfully: StartSet.nupkg
Executing post-install action: restart
Restarting system...
```

### Summary

`cimipkg` streamlines the creation and deployment of `.nupkg` packages by:
- Automating **version control** and **metadata management** through YAML.
- Supporting **pre-install and post-install scripts**.
- Providing seamless **package signing** with `SignTool`.
- Offering **smart readme inclusion** based on the presence of a description.

This tool replaces complex MSI or WiX packaging with a simple, effective solution for Windows software deployment.

### Installer-Type Packages (vendor setups)

If the payload contains a vendor-supplied installer (e.g. Autodesk Maya,
Unity, Adobe Acrobat) you **do not** need to set any special flag.
Simply leave `install_location` blank:

```yaml
product:
  name: Maya
  version: 2025.0
  identifier: ca.emilycarru.winadmins.Maya
  developer: Autodesk
install_location:          # ← blank = installer-type
postinstall_action: none
```

When this package installs:

1. Chocolatey unzips the `.nupkg` to `C:\ProgramData\chocolatey\lib\Maya`.
2. `scripts\preinstall.ps1` (if present) runs first to configure installer arguments.
3. `payload\setup.exe` (or the first `.msi`) is executed in place with `Install-ChocolateyPackage`
   using `-UseOriginalLocation`, so there is no second copy to `%TEMP%`.
4. Your `postinstall*.ps1` scripts (if any) run after the installer exits for configuration tasks.

#### Customizing Installer Arguments

Use `scripts/preinstall.ps1` to override installer arguments by setting the global hashtable:

```powershell
# scripts/preinstall.ps1
$global:CimianInstallerArgs = @{
    silentArgs = "/S /LOG=Maya.log ACCEPT_EULA=YES"
    validExitCodes = @(0, 3010)
}

Write-Host "Maya installer arguments configured: $($global:CimianInstallerArgs.silentArgs)"
```

**Important**: Do not manually call installers in `postinstall.ps1` scripts for installer-type packages. The installer is automatically executed by `Install-ChocolateyPackage`. Use postinstall scripts only for post-installation configuration (license files, shortcuts, registry settings, etc.).

#### What NOT to Include in Postinstall Scripts

For installer-type packages, **avoid** these patterns in `postinstall.ps1`:

```powershell
# DON'T DO THIS - Duplicate installer calls
Start-Process "msiexec.exe" -ArgumentList "/i setup.msi /qn" -Wait
Start-Process -FilePath "setup.exe" -ArgumentList "/S" -Wait
& $setupExe /silent
Invoke-Expression "setup.exe /quiet"
cmd /c "setup.exe /unattended"

# DON'T DO THIS - Manual installer execution
$proc = Start-Process -FilePath $setupExe -ArgumentList $arguments -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "Installation failed" }
```

Instead, use postinstall scripts for configuration tasks only:

```powershell
# ✅ DO THIS - Post-installation configuration
# Copy license files
Copy-Item -Path "$PSScriptRoot\license.lic" -Destination "C:\ProgramData\MyApp\" -Force

# Remove unwanted shortcuts
Remove-Item "C:\Users\Public\Desktop\Unwanted*.lnk" -Force -ErrorAction SilentlyContinue

# Configure registry settings
New-ItemProperty -Path "HKLM:\SOFTWARE\MyApp" -Name "LicenseServer" -Value "license.company.com"

# Create uninstall scripts
"C:\Program Files\MyApp\uninstall.exe /S" | Out-File -FilePath "$PSScriptRoot\remove.bat"
```

All other packages that need to copy files (fonts, config, etc.) keep
their original behaviour by specifying an `install_location`.

#### Example – content-only package

```shell
project/
├── payload/
│   ├── Avenir Next LT Pro Bold.ttf
│   └── …
└── build-info.yaml
```

```yaml
product:
  name: FontsLibrary
  version: 2025.03.08
  identifier: ca.emilycarru.winadmins.FontsLibrary
  developer: EmilyCarrU
install_location: 'C:\Windows\Fonts'   # copy-type package
postinstall_action: none
```

Fonts are copied to `C:\Windows\Fonts\` during install.

#### Example – script-only package

```shell
project/
├── payload/                   # Empty (no files to copy)
├── scripts/
│   ├── preinstall.ps1         # Runs before installation
│   └── postinstall.ps1        # Runs after installation
└── build-info.yaml
```

```yaml
product:
  name: ScriptRunner
  version: 2025.03.08
  identifier: ca.emilycarru.winadmins.ScriptRunner
  developer: EmilyCarrU
install_location:           # No files to copy
postinstall_action: none
```

This package runs the `preinstall.ps1` and `postinstall.ps1` scripts without copying any files. It is ideal for tasks like configuring system settings or running maintenance scripts.

## Cryptographic Package Signing

`cimipkg` supports **NuGet-style cryptographic signing** that embeds signature metadata directly in the package's `build-info.yaml` file. This provides package integrity verification without requiring external signature files.

### Signing Process

When the `-sign` flag is used, `cimipkg` performs the following steps:

1. **Content Hashing** - Calculates SHA256 hashes of all payload files and PowerShell scripts
2. **Package Hash Generation** - Creates a deterministic hash of the entire package contents
3. **Certificate Integration** - Uses Windows Certificate Store (same certificates as SignTool)
4. **Cryptographic Signing** - Signs the package hash using RSA-SHA256
5. **Metadata Embedding** - Embeds complete signature metadata in `build-info.yaml`

### Signature Metadata Structure

The signature is embedded in the `build-info.yaml` as a `signature` section:

```yaml
signature:
  algorithm: "SHA256withRSA"
  certificate:
    subject: "CN=Company Name, O=Organization, C=US"
    issuer: "CN=Certificate Authority"
    thumbprint: "A1B2C3D4E5F6789012345678901234567890ABCD"
    serial_number: "1234567890ABCDEF"
    not_before: "2024-01-01T00:00:00Z"
    not_after: "2025-12-31T23:59:59Z"
  package_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  content_hash: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
  signed_hash: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b"
  timestamp: "2024-12-20T10:30:45Z"
  version: "1.0"
```

### Certificate Requirements

- **Windows Certificate Store** - Certificates must be installed in the current user's personal certificate store
- **Code Signing Capability** - Certificates must have the "Code Signing" enhanced key usage
- **Private Key Access** - Private key must be available for signing operations
- **SignTool Compatibility** - Uses the same certificate infrastructure as Windows SignTool

### Signature Verification

Package integrity can be verified by:

1. **Extracting signature metadata** from `build-info.yaml`
2. **Recalculating content hashes** of payload files and scripts
3. **Verifying signed hash** using the certificate public key
4. **Checking certificate validity** and trust chain
5. **Comparing timestamp** against certificate validity period

### Format-Specific Signing Behavior

#### .pkg Packages (Modern)
- Signature metadata embedded in `build-info.yaml` inside the ZIP
- No external signature files required
- Compatible with **sbin-installer** verification
- Supports deterministic package verification

#### .nupkg Packages (Legacy)  
- Uses traditional NuGet package signing (`nuget sign`)
- Creates external `.signature.p7s` signature file
- Compatible with **Chocolatey** and **NuGet** verification
- Follows NuGet package signing standards

### Certificate Auto-Discovery

`cimipkg` automatically discovers suitable certificates:

1. **Search Personal Store** - Looks in current user's personal certificate store
2. **Filter by Usage** - Only considers certificates with "Code Signing" capability
3. **Check Private Key** - Verifies private key is available and accessible
4. **Select Best Match** - Chooses certificate with longest validity period

Override automatic selection with `-thumbprint` parameter:

```bash
cimipkg -v 1.2.3 -sign -thumbprint "A1B2C3D4E5F6789012345678901234567890ABCD"
```

### Verification Integration

The embedded signature metadata enables:

- **sbin-installer** package integrity verification
- **Enterprise deployment** with cryptographic assurance  
- **Supply chain security** through certificate validation
- **Tamper detection** via content hash verification
- **Audit trails** with timestamp and certificate information
