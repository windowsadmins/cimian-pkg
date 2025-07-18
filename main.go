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

// ───────────────────── helper: detect installer-type ─────────────────────
func isInstallerPackage(bi *BuildInfo, hasPayload bool) bool {
	if !hasPayload {
		return false
	}
	return strings.TrimSpace(bi.InstallLocation) == ""
}

// NormalizePath converts a Windows-style path to a POSIX-style path.
func NormalizePath(input string) string {
	return filepath.FromSlash(strings.ReplaceAll(input, "\\", "/"))
}

// readBuildInfo reads and parses the build-info.yaml file from the project directory.
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

// parseVersion validates and normalizes the version string to a format suitable for Chocolatey.
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

// createProjectDirectory creates the necessary subdirectories in the project directory.
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

// normalizeInstallLocation ensures the install location ends with a backslash
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

// includePreinstallScripts turns the preinstall.ps1 into
// tools/chocolateyBeforeModify.ps1
//
// The generated file now starts with the same header we use in
// chocolateyInstall.ps1 so behaviour (-Stop, UTF-8, logging) is identical.
func includePreinstallScripts(projectDir string) error {
	preScripts, err := getPreinstallScripts(projectDir)
	if err != nil {
		return err
	}
	if len(preScripts) == 0 {
		return nil // nothing to do
	}

	beforePath := filepath.Join(projectDir, "tools", "chocolateyBeforeModify.ps1")
	if err := os.MkdirAll(filepath.Dir(beforePath), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create tools directory: %w", err)
	}

	var sb strings.Builder
	// ── keep behaviour in sync with chocolateyInstall.ps1 ───────────────
	sb.WriteString("$ErrorActionPreference = 'Stop'\n")
	sb.WriteString("Write-Verbose 'Running chocolateyBeforeModify.ps1'\n\n")

	// ── append each preinstall*.ps1 in lexical order ────────────────────
	for _, script := range preScripts {
		content, err := os.ReadFile(filepath.Join(projectDir, "scripts", script))
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", script, err)
		}
		sb.WriteString("# ────────────────────────────────\n")
		sb.WriteString("# Contents of " + script + "\n")
		sb.Write(content)
		if !strings.HasSuffix(sb.String(), "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("# ────────────────────────────────\n\n")
	}

	return os.WriteFile(beforePath, []byte(sb.String()), 0644)
}

// createChocolateyInstallScript generates tools/chocolateyInstall.ps1.
//   - If InstallerTypePayload == true we launch the embedded installer in place.
//   - Otherwise we copy the payload tree to InstallLocation, *using –LiteralPath*
//     to handle filenames containing [, ], *, ? etc.
func createChocolateyInstallScript(bi *BuildInfo, projectDir string, installerPkg bool, hasPayload bool) error {
	scriptPath := filepath.Join(projectDir, "tools", "chocolateyInstall.ps1")

	var sb strings.Builder
	sb.WriteString("$ErrorActionPreference = 'Stop'\n\n")

	switch {
	case !hasPayload:
		sb.WriteString("Write-Host 'No payload files found – script-only package.'\n")

	case installerPkg:
		sb.WriteString(`
$payloadDir = Join-Path $PSScriptRoot '..\payload'
$installer  = Get-ChildItem -Path $payloadDir -Include *.exe,*.msi -File -Recurse | Select-Object -First 1
if (-not $installer) { Write-Error "No installer found in $payloadDir"; exit 1 }

$pkgArgs = @{
    packageName         = $env:ChocolateyPackageName
    fileType            = if ($installer.Extension -ieq '.msi') { 'msi' } else { 'exe' }
    file                = $installer.FullName
    silentArgs          = '/S'
    useOriginalLocation = $true
}

Install-ChocolateyPackage @pkgArgs
if ($LASTEXITCODE -ne 0) { throw "Installer exited with $LASTEXITCODE" }
`)

	default: // copy-type
		installLocation := normalizeInstallLocation(bi.InstallLocation)
		sb.WriteString("$installLocation = '" + installLocation + "'\n\n")
		sb.WriteString(`
if ($installLocation) { New-Item -ItemType Directory -Force -Path $installLocation | Out-Null }
$payloadRoot = Join-Path $PSScriptRoot '..\payload'
$payloadRoot = [System.IO.Path]::GetFullPath($payloadRoot)

Get-ChildItem -Path $payloadRoot -Recurse | ForEach-Object {
    $fullName = $_.FullName
    $fullName = [Management.Automation.WildcardPattern]::Escape($fullName)
    $relative = $fullName.Substring($payloadRoot.Length).TrimStart('\','/')
    $dest     = Join-Path $installLocation $relative

    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
    } else {
        Copy-Item -LiteralPath $fullName -Destination $dest -Force
        if (-not (Test-Path -LiteralPath $dest)) {
            Write-Error "Failed to copy $fullName"
            exit 1
        }
    }
}
`)
	}

	switch strings.ToLower(bi.PostInstallAction) {
	case "logout":
		sb.WriteString("\nshutdown /l\n")
	case "restart":
		sb.WriteString("\nshutdown /r /t 0\n")
	}

	if err := os.MkdirAll(filepath.Dir(scriptPath), os.ModePerm); err != nil {
		return err
	}
	if err := os.WriteFile(scriptPath, []byte(sb.String()), 0644); err != nil {
		return err
	}

	post, err := getPostinstallScripts(projectDir)
	if err != nil {
		return err
	}
	if len(post) > 0 {
		f, _ := os.OpenFile(scriptPath, os.O_APPEND|os.O_WRONLY, 0600)
		defer f.Close()
		for _, s := range post {
			b, _ := os.ReadFile(filepath.Join(projectDir, "scripts", s))
			f.WriteString("\n# Post-install script: " + s + "\n")
			f.Write(b)
			f.WriteString("\n")
		}
	}
	return nil
}

// helper – Authenticode-sign PowerShell scripts in tools/ directory that get packaged
// Only signs chocolateyInstall.ps1 and chocolateyBeforeModify.ps1, not original scripts in scripts/ folder
// Prefer thumbprint if provided, fallback to subject
func signPowerShellScripts(projectDir, subject, thumbprint string) error {
	// Only sign the generated PowerShell scripts in tools/ directory that get packaged
	var psFiles []string

	// Check for chocolateyInstall.ps1 (always generated)
	chocolateyInstallPath := filepath.Join(projectDir, "tools", "chocolateyInstall.ps1")
	if _, err := os.Stat(chocolateyInstallPath); err == nil {
		psFiles = append(psFiles, chocolateyInstallPath)
	}

	// Check for chocolateyBeforeModify.ps1 (generated from preinstall scripts)
	chocolateyBeforePath := filepath.Join(projectDir, "tools", "chocolateyBeforeModify.ps1")
	if _, err := os.Stat(chocolateyBeforePath); err == nil {
		psFiles = append(psFiles, chocolateyBeforePath)
	}

	if len(psFiles) == 0 {
		logger.Debug("No PowerShell scripts found in tools/ directory to sign")
		return nil
	}

	// Sign each PowerShell file using signtool
	signedCount := 0
	var signErrors []string

	for _, psFile := range psFiles {
		var args []string

		// Use thumbprint if provided, otherwise use certificate subject name
		if thumbprint != "" {
			args = []string{
				"sign",
				"/sha1", thumbprint,
				"/fd", "SHA256",
				"/tr", "http://timestamp.digicert.com",
				"/td", "SHA256",
				"/v",
				psFile,
			}
			logger.Debug("Signing with thumbprint: %s", thumbprint)
		} else if subject != "" {
			args = []string{
				"sign",
				"/n", subject,
				"/fd", "SHA256",
				"/tr", "http://timestamp.digicert.com",
				"/td", "SHA256",
				"/v",
				psFile,
			}
			logger.Debug("Signing with certificate name: %s", subject)
		} else {
			signErrors = append(signErrors, fmt.Sprintf("no certificate specified for %s", psFile))
			continue
		}

		if err := runCommand("signtool", args...); err != nil {
			signErrors = append(signErrors, fmt.Sprintf("failed to sign %s: %v", psFile, err))
			logger.Debug("Warning: Failed to sign %s: %v", psFile, err)
		} else {
			logger.Debug("Signed PowerShell script: %s", psFile)
			signedCount++
		}
	}

	if len(signErrors) > 0 {
		logger.Debug("Warning: %d of %d scripts could not be signed", len(signErrors), len(psFiles))
		for _, errMsg := range signErrors {
			logger.Debug("  - %s", errMsg)
		}
		// Don't fail the build, just warn
	}

	logger.Debug("Successfully signed %d of %d PowerShell scripts", signedCount, len(psFiles))
	return nil
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

	payloadPath := filepath.Join(projectDir, "payload")
	hasPayloadFiles, err := payloadDirectoryHasFiles(payloadPath)
	if err != nil {
		logger.Fatal("Error checking payload folder: %v", err)
	}

	installerPkg := isInstallerPackage(buildInfo, hasPayloadFiles)

	if hasPayloadFiles && !installerPkg && buildInfo.InstallLocation == "" {
		logger.Fatal("Error: 'install_location' must be specified when payload exists and the package is not an installer.")
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
	if err := createChocolateyInstallScript(buildInfo, projectDir, installerPkg, hasPayloadFiles); err != nil {
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
