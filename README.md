# cimipkg - Cimian Package Builder

A standalone tool for creating `.pkg` and `.nupkg` packages for [Cimian](https://github.com/windowsadmins/cimian) software deployment — or any deployment system that uses the `.pkg` format.

## Overview

`cimipkg` reads a `build-info.yaml` file describing your package and produces signed, versioned `.pkg` archives containing payload files and lifecycle scripts.

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
# Build a package from a project directory
cimipkg <project-directory>

# Build with verbose output
cimipkg --verbose <project-directory>

# Build legacy .nupkg format
cimipkg --nupkg <project-directory>

# Create a new project scaffold
cimipkg --new <directory-name>
```

## Project Structure

A cimipkg project directory contains:

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

### Dynamic Versioning

Use placeholders in the version field:

- `${TIMESTAMP}` — `YYYY.MM.DD.HHMM`
- `${DATE}` — `YYYY.MM.DD`
- `${DATETIME}` — `YYYY.MM.DD.HHMMSS`
- `${version}` — reference the resolved version in the name field

## License

Apache License 2.0 — see [LICENSE](LICENSE).
