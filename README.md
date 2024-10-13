# gorillapkg

## Introduction

`gorillapkg` is a tool for building `.nupkg` packages for deploying software on Windows in a consistent, repeatable manner. It leverages **NuGet** for package creation and **Chocolatey** (or **Gorilla**) for deployment, with support for **pre- and post-installation scripts**.

This tool simplifies the complexities of deployment by abstracting YAML-based configuration and script-based actions, and offers flexible **certificate signing** using Windows `SignTool`.

### Features

- **Dynamic File Inclusion**: Automatically packages all files and folders in the `payload/` directory.
- **Script Support**: Supports **pre-install** and **post-install** scripts executed with **elevated privileges**.
- **Custom Installation Paths**: Configure where the payload files are installed via the YAML configuration.
- **Post-Install Actions**: Supports automatic **logout** or **restart** after package installation.
- **Package Signing with `SignTool`**: Optionally sign packages using a certificate in the Windows Certificate Store.
- **Automated Packaging**: Uses `nuget` CLI to build `.nupkg` packages for deployment with **Chocolatey** or **Gorilla**.
- **YAML-Driven Configuration**: All metadata and installation instructions come from the `build-info.yaml` file.

---

### Prerequisites

#### **For Development:**
- **Go** (to build the `gorillapkg` tool).
- **NuGet CLI** (for generating `.nupkg` packages).

#### **For Deployment:**
- **Chocolatey** or **Gorilla** (for installing `.nupkg` packages).
- **PowerShell** (to run pre- and post-installation scripts).
- **Windows SDK** (for the `SignTool` utility).

---

### Installation

Clone the repository:

```shell
git clone https://github.com/rodchristiansen/gorilla-pkg.git
cd gorilla-pkg
```

---

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

Here’s the structured YAML and the detailed explainer added as a separate section:

```yaml
product:
  identifier: "com.gorillacorp.gorilla"
  version: "1.0.0"
  name: "Gorilla"
  publisher: "Gorilla Corp"
install_location: "C:\\Program Files\\Gorilla"
postinstall_action: "restart"
signing_certificate: "Gorilla Corp EV Certificate"
```

### **Field Descriptions**

- **`identifier`:**  
  A reverse-domain style unique identifier (e.g., `com.gorillacorp.gorilla`). This identifier aligns with NuGet's `<id>` field and ensures that the package is recognized correctly across versions, preventing duplicate or conflicting installs.

- **`version`:**  
  The version of the package. It supports both:
  - **Semantic versioning:** e.g., `1.0.0`  
  - **Date-based versioning:** e.g., `2024.10.12`  
  This allows the system to compare versions during upgrades and determine if a new installation is required.

- **`name`:**  
  A friendly display name for the product, shown during installation or in the system’s package manager.

- **`publisher`:**  
  Refers to the organization or company that distributes the package, ensuring users know the source of the software.

- **`install_location`:**  
  The default directory where the package will be installed (e.g., `C:\Program Files\Gorilla`). This can be adjusted if needed during each build.

- **`postinstall_action`:**  
  Specifies the action to be taken after installation. Options include:
  - `none`: No additional action is taken.
  - `logout`: Logs out the current user.
  - `restart`: Restarts the system immediately.

- **`signing_certificate`:**  
  The name of the certificate to be used for signing the package using `SignTool`. Digital signing ensures the authenticity and integrity of the package, making it trusted by Windows.


### Usage

To create a new package:

```shell
gorillapkg <project_dir>
```

This command will:
1. Validate the project structure.
2. Convert `build-info.yaml` into a `.nuspec` manifest.
3. Run the `nuget pack` command to generate the `.nupkg` package.
4. Optionally sign the package if `identity` is specified in the YAML file.
5. Perform any specified post-install action (logout or restart).

---

### Script Execution

- **Pre-Install**: `scripts/preinstall.ps1` runs before copying files to the target directory.
- **Post-Install**: `scripts/postinstall.ps1` runs after installation and acts as Chocolatey’s `chocolateyInstall.ps1`.
- Scripts can handle tasks like **service setup**, **configuration**, or **clean-up**.

---

### Package Signing with `SignTool`

`gorillapkg` supports signing `.nupkg` packages using the **Windows `SignTool`** if the `identity` key is specified in the YAML configuration.

#### **Setup Instructions for `SignTool`:**

1. **Install the Windows SDK**:  
   Download and install the SDK from [Microsoft](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/).

2. **Add `SignTool` to Your PATH**:
   Add the path to `SignTool.exe` to your system’s PATH:
   - `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe`

3. **Ensure Certificate Availability**:
   The certificate specified by the `identity` key must be installed in the **Personal Certificate Store**:
   - Open **Certificate Manager**: `certmgr.msc`
   - Navigate to **Personal → Certificates**.
   - Ensure your certificate is listed there.

4. **Test `SignTool` Setup**:
   Run the following command to confirm `SignTool` is correctly installed:

   ```shell
   signtool
   ```

---

### Example Commands

1. **Build the `.nupkg`**:

   ```shell
   nuget pack gorilla.nuspec
   ```

2. **Install with Chocolatey**:

   ```shell
   choco install Gorilla --source="path/to/package"
   ```

3. **Install with Gorilla**:

   ```shell
   gorilla install Gorilla --source="path/to/package"
   ```

---

### Handling Post-Install Actions

The `postinstall_action` key in the YAML file allows for **system-level actions** post installation:
- **`none`**: No action is performed.
- **`logout`**: The current user is logged out.
- **`restart`**: The system restarts immediately.

The actions are executed using PowerShell commands during installation.

---

### Example Output

When `gorillapkg` runs, it will:
- Validate the project and generate a `.nuspec` manifest.
- Build the `.nupkg` package.
- Use `SignTool` to sign the package (if identity is provided).
- Trigger post-install actions (logout or restart, if specified).

Example output:

```
Parsed version: 1.0.0
Building package: Gorilla
Running command: nuget pack Gorilla.nuspec
Signing package: Gorilla.nupkg with identity: Gorilla Corp EV Certificate
Package signed successfully.
Executing post-install action: restart
Restarting system...
```

---

### Summary

`gorillapkg` simplifies the creation and deployment of `.nupkg` packages while offering:
- **Version control and metadata management** through YAML.
- **Pre- and post-installation scripting** for advanced customization.
- **Seamless certificate signing** with `SignTool`.
- **Automatic logout or restart actions** after installation.

This tool eliminates the complexity of MSI and WiX, providing a streamlined solution for software deployment on Windows.

