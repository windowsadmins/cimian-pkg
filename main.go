//cmd/cimipkg/main.go

package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/windowsadmins/cimian-pkg/internal/logging"

	"gopkg.in/yaml.v2"
)

// BuildInfo holds package build information parsed from YAML.
type BuildInfo struct {
	InstallLocation    string `yaml:"install_location"`
	PostInstallAction  string `yaml:"postinstall_action"`
	SigningCertificate string `yaml:"signing_certificate,omitempty"`
	SigningThumbprint  string `yaml:"signing_thumbprint,omitempty"`
	Product            struct {
		Identifier  string `yaml:"identifier"`
		Version     string `yaml:"version"`
		Name        string `yaml:"name"`
		Developer   string `yaml:"developer"`
		Description string `yaml:"description,omitempty"`
	} `yaml:"product"`
}

// Package defines the structure of a .nuspec package.
type Package struct {
	XMLName  xml.Name  `xml:"package"`
	Metadata Metadata  `xml:"metadata"`
	Files    []FileRef `xml:"files>file,omitempty"`
}

// Metadata stores the package metadata.
type Metadata struct {
	ID          string `xml:"id"`
	Version     string `xml:"version"`
	Authors     string `xml:"authors"`
	Description string `xml:"description"`
	Tags        string `xml:"tags,omitempty"`
	Readme      string `xml:"readme,omitempty"`
}

// FileRef defines the source and target paths for files.
type FileRef struct {
	Src    string `xml:"src,attr"`
	Target string `xml:"target,attr"`
}

var (
	intuneWinFlag bool
	logger        *logging.Logger
)

func setupLogging(verbose bool) {
	logger = logging.New(verbose)
}

func verifyProjectStructure(projectDir string) error {
	payloadPath := filepath.Join(projectDir, "payload")
	scriptsPath := filepath.Join(projectDir, "scripts")

	payloadExists := false
	scriptsExists := false

	if _, err := os.Stat(payloadPath); !os.IsNotExist(err) {
		payloadExists = true
	}
	if _, err := os.Stat(scriptsPath); !os.IsNotExist(err) {
		scriptsExists = true
	}

	if !payloadExists && !scriptsExists {
		return fmt.Errorf("either 'payload' or 'scripts' directory must exist in the project directory")
	}

	buildInfoPath := filepath.Join(projectDir, "build-info.yaml")
	if _, err := os.Stat(buildInfoPath); os.IsNotExist(err) {
		return fmt.Errorf("'build-info.yaml' file is missing in the project directory")
	}

	return nil
}

func NormalizePath(input string) string {
	return filepath.FromSlash(strings.ReplaceAll(input, "\\", "/"))
}

func readBuildInfo(projectDir string) (*BuildInfo, error) {
	path := filepath.Join(projectDir, "build-info.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading build-info.yaml: %w", err)
	}

	var buildInfo BuildInfo
	if err := yaml.Unmarshal(data, &buildInfo); err != nil {
		return nil, fmt.Errorf("error parsing YAML: %w", err)
	}

	return &buildInfo, nil
}

func parseVersion(versionStr string) (string, error) {
	parts := strings.Split(versionStr, ".")
	var numericParts []string

	for _, part := range parts {
		if _, err := strconv.Atoi(part); err != nil {
			return "", fmt.Errorf("invalid version part: %q is not a number", part)
		}
		numericParts = append(numericParts, part)
	}

	return strings.Join(numericParts, "."), nil
}

func createProjectDirectory(projectDir string) error {
	subDirs := []string{
		"payload",
		"scripts",
		"build",
		"tools",
	}

	for _, subDir := range subDirs {
		fullPath := filepath.Join(projectDir, subDir)
		if err := os.MkdirAll(fullPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
		}
	}
	return nil
}

func normalizeInstallLocation(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	if !strings.HasSuffix(path, `\`) {
		path += `\`
	}
	return path
}

// getPreinstallScripts returns all scripts matching `preinstall*.ps1`
func getPreinstallScripts(projectDir string) ([]string, error) {
	scriptsDir := filepath.Join(projectDir, "scripts")
	var preScripts []string
	if _, err := os.Stat(scriptsDir); os.IsNotExist(err) {
		return preScripts, nil
	}

	entries, err := os.ReadDir(scriptsDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Type().IsRegular() &&
			strings.HasPrefix(strings.ToLower(entry.Name()), "preinstall") &&
			strings.HasSuffix(strings.ToLower(entry.Name()), ".ps1") {
			preScripts = append(preScripts, entry.Name())
		}
	}

	sort.Strings(preScripts)
	return preScripts, nil
}

// getPostinstallScripts returns all scripts matching `postinstall*.ps1`
func getPostinstallScripts(projectDir string) ([]string, error) {
	scriptsDir := filepath.Join(projectDir, "scripts")
	var postScripts []string
	if _, err := os.Stat(scriptsDir); os.IsNotExist(err) {
		return postScripts, nil
	}

	entries, err := os.ReadDir(scriptsDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Type().IsRegular() &&
			strings.HasPrefix(strings.ToLower(entry.Name()), "postinstall") &&
			strings.HasSuffix(strings.ToLower(entry.Name()), ".ps1") {
			postScripts = append(postScripts, entry.Name())
		}
	}

	sort.Strings(postScripts)
	return postScripts, nil
}

// includePreinstallScripts bundles all preinstall*.ps1 into chocolateyBeforeModify.ps1
func includePreinstallScripts(projectDir string) error {
	preScripts, err := getPreinstallScripts(projectDir)
	if err != nil {
		return err
	}
	if len(preScripts) == 0 {
		return nil
	}

	// Create or overwrite chocolateyBeforeModify.ps1 with concatenation of all preinstall scripts.
	beforeModifyPath := filepath.Join(projectDir, "tools", "chocolateyBeforeModify.ps1")
	var combined []byte

	for _, script := range preScripts {
		content, err := os.ReadFile(filepath.Join(projectDir, "scripts", script))
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", script, err)
		}
		combined = append(combined, []byte(fmt.Sprintf("# Contents of %s\n", script))...)
		combined = append(combined, content...)
		combined = append(combined, []byte("\n")...)
	}

	if err := os.MkdirAll(filepath.Dir(beforeModifyPath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create tools directory: %w", err)
	}
	if err := os.WriteFile(beforeModifyPath, combined, 0644); err != nil {
		return fmt.Errorf("failed to write chocolateyBeforeModify.ps1: %w", err)
	}
	return nil
}

// createChocolateyInstallScript generates chocolateyInstall.ps1 and appends postinstall scripts.
func createChocolateyInstallScript(buildInfo *BuildInfo, projectDir string) error {
	scriptPath := filepath.Join(projectDir, "tools", "chocolateyInstall.ps1")

	// Check if the payload folder has any files
	payloadPath := filepath.Join(projectDir, "payload")
	hasPayloadFiles, err := payloadDirectoryHasFiles(payloadPath)
	if err != nil {
		return fmt.Errorf("failed to check payload folder: %w", err)
	}

	installLocation := normalizeInstallLocation(buildInfo.InstallLocation)
	var scriptBuilder strings.Builder
	scriptBuilder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	scriptBuilder.WriteString(fmt.Sprintf("$installLocation = '%s'\n\n", installLocation))

	// If the payload folder actually has files, do the normal create/copy
	if hasPayloadFiles {
		scriptBuilder.WriteString(`if ($installLocation -and $installLocation -ne '') {
    try {
        New-Item -ItemType Directory -Force -Path $installLocation | Out-Null
        Write-Host "Created or verified install location: $installLocation"
    } catch {
        Write-Error "Failed to create or access: $installLocation"
        exit 1
    }
} else {
    Write-Host "No install location specified, skipping creation of directories."
}

$payloadPath = "$PSScriptRoot\..\payload"
$payloadPath = [System.IO.Path]::GetFullPath($payloadPath)
$payloadPath = $payloadPath.TrimEnd('\', '/')

Write-Host "Payload path: $payloadPath"
Get-ChildItem -Path $payloadPath -Recurse | ForEach-Object {
    $fullName = $_.FullName
    $relativePath = $fullName.Substring($payloadPath.Length)
    $relativePath = $relativePath.TrimStart('\', '/')
    $destinationPath = Join-Path $installLocation $relativePath

    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
        Write-Host "Created directory: $destinationPath"
    } else {
        Copy-Item -Path $fullName -Destination $destinationPath -Force
        Write-Host "Copied: $($fullName) -> $destinationPath"

        if (-not (Test-Path -Path $destinationPath)) {
            Write-Error "Failed to copy: $($fullName)"
            exit 1
        }
    }
}
`)
	} else {
		// Script-only scenario
		scriptBuilder.WriteString(`Write-Host "No payload files found. Script-only install - skipping directory creation and file copy."
`)
	}

	// Handle post-install action if provided
	if action := strings.ToLower(buildInfo.PostInstallAction); action != "" {
		scriptBuilder.WriteString("\n# Executing post-install action\n")
		switch action {
		case "logout":
			scriptBuilder.WriteString("Write-Host 'Logging out...'\nshutdown /l\n")
		case "restart":
			scriptBuilder.WriteString("Write-Host 'Restarting system...'\nshutdown /r /t 0\n")
		case "none":
			scriptBuilder.WriteString("Write-Host 'No post-install action required.'\n")
		default:
			return fmt.Errorf("unsupported post-install action: %s", action)
		}
	}

	// Write the base chocolateyInstall.ps1
	if err := os.MkdirAll(filepath.Dir(scriptPath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create tools directory: %w", err)
	}
	if err := os.WriteFile(scriptPath, []byte(scriptBuilder.String()), 0644); err != nil {
		return fmt.Errorf("failed to write chocolateyInstall.ps1: %w", err)
	}

	// Append postinstall scripts if any
	postScripts, err := getPostinstallScripts(projectDir)
	if err != nil {
		return err
	}
	if len(postScripts) > 0 {
		f, err := os.OpenFile(scriptPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open chocolateyInstall.ps1 for append: %w", err)
		}
		defer f.Close()

		for _, script := range postScripts {
			content, err := os.ReadFile(filepath.Join(projectDir, "scripts", script))
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", script, err)
			}
			if _, err := f.WriteString(fmt.Sprintf("\n# Post-install script: %s\n", script)); err != nil {
				return err
			}
			if _, err := f.Write(content); err != nil {
				return err
			}
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

// helper – Authenticode-sign all PowerShell scripts in the project ------------
// Prefer thumbprint if provided, fallback to subject
func signPowerShellScripts(projectDir, subject, thumbprint string) error {
	var psFiles []string
	if err := filepath.WalkDir(projectDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".ps1") {
			psFiles = append(psFiles, p)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(psFiles) == 0 {
		return nil
	}

	var b strings.Builder
	b.WriteString("\n")
	if thumbprint != "" {
		b.WriteString("$thumb = '" + thumbprint + "'\n")
		b.WriteString("$cert  = Get-ChildItem Cert:\\CurrentUser\\My\\$thumb\n")
		b.WriteString("if (-not $cert) { Write-Error 'Signing cert not found by thumbprint'; exit 1 }\n")
	} else {
		b.WriteString("$cert = Get-ChildItem Cert:\\CurrentUser\\My |\n")
		b.WriteString("         Where-Object { $_.Subject -eq '" + subject + "' } |\n")
		b.WriteString("         Select-Object -First 1\n")
		b.WriteString("if (-not $cert) { Write-Error 'Signing cert not found by subject'; exit 1 }\n")
	}
	b.WriteString("\nforeach ($f in @(@'\n")
	for _, f := range psFiles {
		b.WriteString(f + "\n")
	}
	b.WriteString("'@.Trim().Split(\"" + "\n" + "\"))) {\n")
	b.WriteString("    Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com' | Out-Null\n")
	b.WriteString("}\n")

	return runCommand("powershell", "-NoLogo", "-NoProfile", "-NonInteractive",
		"-Command", b.String())
}

// generateNuspec builds the .nuspec file
func generateNuspec(buildInfo *BuildInfo, projectDir string) (string, error) {
	nuspecPath := filepath.Join(projectDir, buildInfo.Product.Name+".nuspec")

	description := buildInfo.Product.Description
	if description == "" {
		description = fmt.Sprintf(
			"%s version %s for %s by %s",
			buildInfo.Product.Name, buildInfo.Product.Version,
			buildInfo.Product.Identifier, buildInfo.Product.Developer,
		)
	}

	nuspec := Package{
		Metadata: Metadata{
			ID:          buildInfo.Product.Identifier,
			Version:     buildInfo.Product.Version,
			Authors:     buildInfo.Product.Developer,
			Description: description,
			Tags:        "admin",
		},
	}

	payloadPath := filepath.Join(projectDir, "payload")
	if _, err := os.Stat(payloadPath); !os.IsNotExist(err) {
		err := filepath.Walk(payloadPath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				relPath, _ := filepath.Rel(projectDir, path)
				relPath = filepath.ToSlash(relPath)
				nuspec.Files = append(nuspec.Files, FileRef{
					Src:    relPath,
					Target: relPath,
				})
			}
			return nil
		})
		if err != nil {
			return "", fmt.Errorf("error walking payload directory: %w", err)
		}
	}

	// Always include chocolateyInstall.ps1
	nuspec.Files = append(nuspec.Files, FileRef{
		Src:    filepath.Join("tools", "chocolateyInstall.ps1"),
		Target: filepath.Join("tools", "chocolateyInstall.ps1"),
	})

	// If we have preinstall scripts, they appear as chocolateyBeforeModify.ps1
	preScripts, err := getPreinstallScripts(projectDir)
	if err != nil {
		return "", err
	}
	if len(preScripts) > 0 {
		// We know chocolateyBeforeModify.ps1 will be created if preinstall scripts exist
		nuspec.Files = append(nuspec.Files, FileRef{
			Src:    filepath.Join("tools", "chocolateyBeforeModify.ps1"),
			Target: filepath.Join("tools", "chocolateyBeforeModify.ps1"),
		})
	}

	// Postinstall scripts are appended directly into chocolateyInstall.ps1 content,
	// so we don't need to add them separately as files (they are not separate tools/* files).
	// They are merged into chocolateyInstall.ps1 content.

	file, err := os.Create(nuspecPath)
	if err != nil {
		return "", fmt.Errorf("failed to create .nuspec file: %w", err)
	}
	defer file.Close()

	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(nuspec); err != nil {
		return "", fmt.Errorf("failed to encode .nuspec: %w", err)
	}

	return nuspecPath, nil
}

func runCommand(command string, args ...string) error {
	logger.Debug("Running: %s %v", command, args)
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func signNuGetPackage(pkgPath, cert string) error {
	return runCommand(
		"nuget", "sign", pkgPath,
		"-CertificateStoreLocation", "CurrentUser",
		"-CertificateStoreName", "My",
		"-CertificateSubjectName", cert,
		"-Timestamper", "http://timestamp.digicert.com",
		"-TimestampHashAlgorithm", "sha256",
		"-Overwrite",
	)
}

func signPackage(pkgPath, cert string) error {
	switch strings.ToLower(filepath.Ext(pkgPath)) {
	case ".nupkg":
		logger.Printf("Signing NuGet package: %s with certificate: %s", pkgPath, cert)
		return signNuGetPackage(pkgPath, cert)
	default:
		logger.Printf("Signing file: %s with certificate: %s", pkgPath, cert)
		return runCommand(
			"signtool", "sign", "/n", cert,
			"/fd", "SHA256", "/tr", "http://timestamp.digicert.com",
			"/td", "SHA256", pkgPath,
		)
	}
}

func checkNuGet() {
	if err := runCommand("nuget", "locals", "all", "-list"); err != nil {
		logger.Fatal(`NuGet is not installed or not in PATH.
You can install it via Chocolatey:
  choco install nuget.commandline`)
	}
}

func payloadDirectoryHasFiles(payloadDir string) (bool, error) {
	if _, err := os.Stat(payloadDir); os.IsNotExist(err) {
		// Payload folder doesn't exist at all
		return false, nil
	}
	hasFiles := false
	err := filepath.Walk(payloadDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// If we find at least one regular file, we consider the payload non-empty
		if !info.IsDir() {
			hasFiles = true
			return filepath.SkipDir
		}
		return nil
	})
	return hasFiles, err
}

// buildIntuneWin wraps the specified .nupkg into a .intunewin that,
// on the target machine, actually installs the .nupkg with Chocolatey.
func buildIntuneWin(nupkgPath string) error {
	// Ensure IntuneWinAppUtil.exe is on PATH
	intuneCmd, err := exec.LookPath("IntuneWinAppUtil.exe")
	if err != nil {
		return fmt.Errorf("IntuneWinAppUtil.exe not found in PATH: %w", err)
	}

	// Create a temporary folder
	tempDir, err := os.MkdirTemp("", "intunewin_*")
	if err != nil {
		return fmt.Errorf("failed to create temp folder: %w", err)
	}
	// Remove temp folder after building the .intunewin
	defer os.RemoveAll(tempDir)

	// Copy the .nupkg into the temp folder
	nupkgName := filepath.Base(nupkgPath)
	destNupkg := filepath.Join(tempDir, nupkgName)
	if err := copyFile(nupkgPath, destNupkg); err != nil {
		return fmt.Errorf("failed to copy nupkg into temp: %w", err)
	}

	// Create an Install.ps1 that installs Chocolatey if missing,
	// extracts <id>/<version> from the .nuspec, renames the .nupkg,
	// and then does choco install/upgrade
	installPS := filepath.Join(tempDir, "Install.ps1")
	psContent := fmt.Sprintf(`# Install.ps1 generated by cimianpkg
param(
    [string]$PkgFile = ".\%s"
)

Write-Host "Checking for Chocolatey..."
$chocoExe = "C:\ProgramData\chocolatey\bin\choco.exe"
if (!(Test-Path $chocoExe)) {
    Write-Host "Chocolatey not found. Installing..."
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

    if (!(Test-Path $chocoExe)) {
        Write-Error 'Failed to install Chocolatey.'
        exit 1
    } else {
        Write-Host 'Chocolatey installed successfully.'
    }
} else {
    Write-Host "Chocolatey found at $chocoExe"
}

Write-Host "Extracting nuspec from $PkgFile to get Package ID and Version"
$tempExtract = Join-Path $env:TEMP ("nuspec_" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempExtract | Out-Null

Expand-Archive -LiteralPath $PkgFile -DestinationPath $tempExtract -Force

$nuspec = Get-ChildItem -Path $tempExtract -Recurse -Filter *.nuspec | Select-Object -First 1
if (!$nuspec) {
    Write-Error "No .nuspec found inside $PkgFile"
    exit 1
}

[xml]$xml = Get-Content $nuspec.FullName
$pkgId      = $xml.package.metadata.id
$pkgVersion = $xml.package.metadata.version

if (!$pkgId -or !$pkgVersion) {
    Write-Error "Unable to parse <id> or <version> from .nuspec"
    exit 1
}

Write-Host "Parsed Package ID = $pkgId, Version = $pkgVersion"

# Rename the .nupkg to <id>.<version>.nupkg so Chocolatey can properly detect it
$newNupkgName = "$($pkgId).$($pkgVersion).nupkg"
if (Test-Path $newNupkgName) {
    Remove-Item $newNupkgName -Force
}

Write-Host "Renaming $PkgFile to $newNupkgName"
Rename-Item -Path $PkgFile -NewName $newNupkgName

# Clean up extracted nuspec files
Remove-Item $tempExtract -Recurse -Force

Write-Host "Checking if $pkgId is already installed locally..."
$alreadyInstalled = $false
$listOutput = choco list --local-only --limit-output --exact $pkgId 2>$null
if ($LASTEXITCODE -eq 0 -and $listOutput -match $pkgId) {
    Write-Host "Package $pkgId is installed. We'll do an upgrade."
    $alreadyInstalled = $true
} else {
    Write-Host "Package $pkgId not installed. We'll do an install."
}

if ($alreadyInstalled) {
    choco upgrade $pkgId --version $pkgVersion --source "." -y --force --allowdowngrade --debug
} else {
    choco install $pkgId --version $pkgVersion --source "." -y --force --allowdowngrade --debug
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Chocolatey install/upgrade of $pkgId successful."
    exit 0
} else {
    Write-Error "Chocolatey failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
`, nupkgName)

	// Write that script to Install.ps1
	if err := os.WriteFile(installPS, []byte(psContent), 0644); err != nil {
		return fmt.Errorf("failed to write Install.ps1: %w", err)
	}

	// Get the base name without extension for consistent naming
	baseName := strings.TrimSuffix(nupkgName, filepath.Ext(nupkgName))
	intunewinName := baseName + ".intunewin"
	outDir := filepath.Dir(nupkgPath)

	// Run IntuneWinAppUtil without -q parameter
	args := []string{
		"-c", tempDir,
		"-s", filepath.Base(installPS),
		"-o", outDir,
	}
	logger.Printf("Running IntuneWinAppUtil.exe with args: %v", args)

	cmd := exec.Command(intuneCmd, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("IntuneWinAppUtil.exe failed: %w", err)
	}

	// Rename the generated Install.intunewin to our desired name
	defaultIntunewin := filepath.Join(outDir, "Install.intunewin")
	finalIntunewin := filepath.Join(outDir, intunewinName)
	if err := os.Rename(defaultIntunewin, finalIntunewin); err != nil {
		return fmt.Errorf("failed to rename .intunewin: %w", err)
	}

	logger.Printf("Created %s in %s", intunewinName, outDir)
	return nil
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// cleanBuildDirectory removes all files from the build directory
func cleanBuildDirectory(projectDir string) error {
	buildDir := filepath.Join(projectDir, "build")
	if err := os.RemoveAll(buildDir); err != nil {
		return fmt.Errorf("failed to clean build directory: %w", err)
	}
	if err := os.MkdirAll(buildDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to recreate build directory: %w", err)
	}
	return nil
}

// createNewProject creates a new project structure at the specified path
func createNewProject(projectPath string) error {
	// Create the main project directory
	if err := os.MkdirAll(projectPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	// Create payload and scripts directories
	dirs := []string{"payload", "scripts"}
	for _, dir := range dirs {
		dirPath := filepath.Join(projectPath, dir)
		if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}

	// Create build-info.yaml template
	buildInfoTemplate := `
product:
  name: NuPkgProjectName
  version: 1.0.0
  developer: ACME Corp
  identifier: com.company.projectname
postinstall_action: none
signing_certificate: 
install_location: \
`

	buildInfoPath := filepath.Join(projectPath, "build-info.yaml")
	if err := os.WriteFile(buildInfoPath, []byte(buildInfoTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create build-info.yaml: %w", err)
	}

	return nil
}

func main() {
	var (
		verbose    bool
		createPath string
	)
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&intuneWinFlag, "intunewin", false, "Also generate a .intunewin from the built .nupkg")
	flag.StringVar(&createPath, "create", "", "Create a new project structure at the specified path")
	flag.Parse()

	setupLogging(verbose)

	if createPath != "" {
		createPath = NormalizePath(createPath)
		logger.Printf("Creating new project at: %s", createPath)
		if err := createNewProject(createPath); err != nil {
			logger.Fatal("Error creating new project: %v", err)
		}
		logger.Success("New project created successfully!")
		return
	}

	if flag.NArg() < 1 {
		logger.Fatal("Usage: %s [options] <project_directory>\n  -intunewin    optional flag to build a .intunewin from the .nupkg\n  -create PATH  create a new project structure at PATH", os.Args[0])
	}
	projectDir := NormalizePath(flag.Arg(0))

	logger.Printf("Using project directory: %s", projectDir)

	if err := verifyProjectStructure(projectDir); err != nil {
		logger.Fatal("Error verifying project structure: %v", err)
	}
	logger.Success("Project structure verified. Proceeding with package creation...")

	// Clean the build directory before proceeding
	if err := cleanBuildDirectory(projectDir); err != nil {
		logger.Fatal("Error cleaning build directory: %v", err)
	}
	logger.Success("Build directory cleaned successfully.")

	buildInfo, err := readBuildInfo(projectDir)
	if err != nil {
		logger.Fatal("Error reading build-info.yaml: %v", err)
	}

	// Check if the payload folder exists and has files
	payloadPath := filepath.Join(projectDir, "payload")
	hasPayloadFiles, err := payloadDirectoryHasFiles(payloadPath)
	if err != nil {
		logger.Fatal("Error checking payload folder: %v", err)
	}

	// Only require install_location if the payload folder actually has files.
	if hasPayloadFiles && buildInfo.InstallLocation == "" {
		logger.Fatal("Error: 'install_location' must be specified in build-info.yaml because your payload folder is not empty.")
	}

	// Validate version format
	if _, err = parseVersion(buildInfo.Product.Version); err != nil {
		logger.Fatal("Error parsing version: %v", err)
	}

	if err := createProjectDirectory(projectDir); err != nil {
		logger.Fatal("Error creating directories: %v", err)
	}
	logger.Success("Directories created successfully.")

	// Include all preinstall scripts
	if err := includePreinstallScripts(projectDir); err != nil {
		logger.Fatal("Error including preinstall scripts: %v", err)
	}

	// Create chocolateyInstall.ps1 (and optionally copy payload / append postinstall scripts)
	if err := createChocolateyInstallScript(buildInfo, projectDir); err != nil {
		logger.Fatal("Error generating chocolateyInstall.ps1: %v", err)
	}

	// Sign PowerShell scripts in tools directory if signing cert is specified
	if buildInfo.SigningCertificate != "" || buildInfo.SigningThumbprint != "" {
		if err := signPowerShellScripts(projectDir, buildInfo.SigningCertificate, buildInfo.SigningThumbprint); err != nil {
			logger.Fatal("Error signing PowerShell scripts: %v", err)
		}
	}

	nuspecPath, err := generateNuspec(buildInfo, projectDir)
	if err != nil {
		logger.Fatal("Error generating .nuspec: %v", err)
	}
	defer os.Remove(nuspecPath)
	logger.Success(".nuspec generated at: %s", nuspecPath)

	checkNuGet()

	buildDir := filepath.Join(projectDir, "build")
	builtPkgName := buildInfo.Product.Name + "-" + buildInfo.Product.Version + ".nupkg"
	builtPkgPath := filepath.Join(buildDir, builtPkgName)

	if err := runCommand("nuget", "pack", nuspecPath, "-OutputDirectory", buildDir, "-NoPackageAnalysis", "-NoDefaultExcludes"); err != nil {
		logger.Fatal("Error creating package: %v", err)
	}

	searchPattern := filepath.Join(buildDir, buildInfo.Product.Identifier+"*.nupkg")
	matches, _ := filepath.Glob(searchPattern)

	var finalPkgPath string
	if len(matches) > 0 {
		logger.Printf("Renaming package: %s to %s", matches[0], builtPkgPath)
		if err := os.Rename(matches[0], builtPkgPath); err != nil {
			logger.Fatal("Failed to rename package: %v", err)
		}
		finalPkgPath = builtPkgPath
	} else {
		logger.Printf("Package matching pattern not found, using: %s", builtPkgPath)
		finalPkgPath = builtPkgPath
	}

	// Sign if specified
	if buildInfo.SigningCertificate != "" {
		if err := signPackage(finalPkgPath, buildInfo.SigningCertificate); err != nil {
			logger.Fatal("Failed to sign package %s: %v", finalPkgPath, err)
		}
	} else {
		logger.Printf("No signing certificate provided. Skipping signing.")
	}

	// Optional: remove the tools directory
	toolsDir := filepath.Join(projectDir, "tools")
	if err := os.RemoveAll(toolsDir); err != nil {
		logger.Warning("Warning: Failed to remove tools directory: %v", err)
	} else {
		logger.Success("Tools directory removed successfully.")
	}

	logger.Success("Package created successfully: %s", finalPkgPath)

	// If -intunewin was passed, generate the .intunewin
	if intuneWinFlag {
		logger.Printf("User requested .intunewin generation. Wrapping .nupkg into .intunewin ...")
		if err := buildIntuneWin(finalPkgPath); err != nil {
			logger.Fatal("Failed to build .intunewin: %v", err)
		}
	}

	logger.Success("Done.")
}
