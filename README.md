# gorillapkg

## Introduction

`gorillapkg` is a tool for building `.nupkg` packages for deploying software on Windows in a consistent, repeatable manner. It leverages `nuget` for creating packages and `choco` for deployment.

This tool allows for pre- and post-installation scripts, dynamic file inclusion, and version control, all guided by a `build-info.yaml` file. 

### Features

- **Dynamic File Inclusion**: Automatically includes all files and folders inside the `payload/` directory into the `.nupkg` package.
- **Script Support**: Supports pre-install and post-install scripts (with elevated privileges) using PowerShell.
- **Custom Installation Paths**: Specify a custom installation path for the payload via the YAML configuration.
- **Automated Packaging with Chocolatey**: Uses the `nuget` CLI to build `.nupkg` packages.
- **YAML Configuration**: All instructions for the package (metadata, scripts, paths) come from the `build-info.yaml` file.


### Prerequisites

#### **For Development:**
- **Go** (required to build the `gorillapkg` tool)
- **NuGet CLI** (for `.nupkg` generation)

#### **For Deployment:**
- **Chocolatey** or **Gorilla** (for installing packages via `choco`)
- **PowerShell** (for running pre- and post-install scripts)
  

### Installation

Clone the repository:

```bash
git clone https://github.com/rodchristiansen/gorilla-pkg.git
cd gorilla-pkg
```


### Folder Structure for Packages

```
project/
├── payload/                   # Files/folders to be written to disk
│   └── example.txt
├── scripts/                   # Pre-/Post-install scripts
│   ├── preinstall.ps1         # Pre-install script
│   ├── postinstall.ps1        # Post-install chocolateyInstall script
└── build-info.yaml            # Metadata for package generation
```


### YAML Configuration: `build-info.yaml`

The `build-info.yaml` file defines the package metadata:

```yaml
product:
  name: "Gorilla"
  version: "1.0.0"
  manufacturer: "Gorilla Corp"
install_path: "C:\Program Files\Gorilla"
```


### Usage

To create a new package:

```bash
gorillapkg <project_dir>
```

This will:
1. Validate the project structure.
2. Convert `build-info.yaml` into a `.nuspec` manifest.
3. Call the `nuget pack` command to generate a `.nupkg` package.


### Script Execution

- **Pre-Install**: `scripts/preinstall.ps1` runs before files are copied to the target directory.
- **Post-Install**: `scripts/postinstall.ps1` serves as Chocolatey’s `chocolateyInstall.ps1` and runs after files are copied.
- Scripts can perform any necessary setup, service configuration, or cleanup tasks.


### Example Command to Build and Install

1. **Build the `.nupkg`**:
   ```bash
   nuget pack gorilla.nuspec
   ```

2. **Install with Chocolatey**:
   ```bash
   choco install Gorilla --source="path/to/package"
   ```


With `gorillapkg`, you can simplify the creation of `.nupkg` packages while maintaining full control over the process through YAML configuration and scripting. This tool eliminates the pain points of working with MSI and WiX, providing a straightforward, maintainable solution for software deployment.
