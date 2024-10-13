package main

import (
    "encoding/xml"
    "flag"
    "fmt"
    "gopkg.in/yaml.v2"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
)

// BuildInfo holds package build information parsed from YAML.
type BuildInfo struct {
    InstallLocation    string `yaml:"install_location"`
    PostInstallAction  string `yaml:"postinstall_action"`
    SigningCertificate string `yaml:"signing_certificate,omitempty"`
    Product            struct {
        Identifier string `yaml:"identifier"`
        Version    string `yaml:"version"`
        Name       string `yaml:"name"`
        Publisher  string `yaml:"publisher"`
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
}

// FileRef defines the source and target paths for files.
type FileRef struct {
    Src    string `xml:"src,attr"`
    Target string `xml:"target,attr"`
}

// setupLogging configures log output based on verbosity.
func setupLogging(verbose bool) {
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    if verbose {
        log.SetOutput(os.Stdout)
    } else {
        log.SetOutput(os.Stderr)
    }
}

// verifyProjectStructure checks that required files and folders exist.
func verifyProjectStructure(projectDir string) error {
    requiredPaths := []string{
        "build-info.yaml",
        "payload", // Payload folder must exist
        "scripts", // Scripts folder must exist
    }

    for _, path := range requiredPaths {
        fullPath := filepath.Join(projectDir, path)
        if _, err := os.Stat(fullPath); os.IsNotExist(err) {
            return fmt.Errorf("required path %s is missing", fullPath)
        }
    }
    return nil
}

// NormalizePath ensures paths use consistent separators across platforms.
func NormalizePath(input string) string {
    return filepath.FromSlash(strings.ReplaceAll(input, "\\", "/"))
}

// getStandardDirectories returns a map of standard Windows directories with their identifiers.
func getStandardDirectories() map[string]string {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        log.Fatalf("Failed to get user's home directory: %v", err)
    }

    return map[string]string{
        "C:\\Program Files":                                "ProgramFilesFolder",
        "C:\\Program Files (x86)":                          "ProgramFiles6432Folder",
        "C:\\Program Files\\Common Files":                  "CommonFilesFolder",
        "C:\\Program Files\\Common Files (x86)":            "CommonFiles6432Folder",
        "C:\\ProgramData":                                  "CommonAppDataFolder",
        "C:\\Windows":                                      "WindowsFolder",
        "C:\\Windows\\System32":                            "SystemFolder",
        "C:\\Windows\\SysWOW64":                            "System64Folder",
        "C:\\Windows\\Fonts":                               "FontsFolder",
        filepath.Join(homeDir, "AppData", "Local"):         "LocalAppDataFolder",
        filepath.Join(homeDir, "AppData", "Roaming"):       "AppDataFolder",
        filepath.Join(homeDir, "Desktop"):                  "DesktopFolder",
        filepath.Join(homeDir, "Documents"):                "PersonalFolder",
        filepath.Join(homeDir, "Favorites"):                "FavoritesFolder",
        filepath.Join(homeDir, "My Pictures"):              "MyPicturesFolder",
        filepath.Join(homeDir, "NetHood"):                  "NetHoodFolder",
        filepath.Join(homeDir, "PrintHood"):                "PrintHoodFolder",
        filepath.Join(homeDir, "Recent"):                   "RecentFolder",
        filepath.Join(homeDir, "SendTo"):                   "SendToFolder",
        filepath.Join(homeDir, "Start Menu"):               "StartMenuFolder",
        filepath.Join(homeDir, "Startup"):                  "StartupFolder",
        "C:\\Windows\\System":                              "System16Folder",
        "C:\\Windows\\Temp":                                "TempFolder",
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local": "LocalAppDataFolder",
    }
}

// resolveInstallLocation ensures the install location is valid, using standard directories if applicable.
func resolveInstallLocation(installLocation string, dirs map[string]string) string {
    normalized := NormalizePath(installLocation)

    // Check if the path matches any of the standard Windows directories.
    if identifier, exists := dirs[normalized]; exists {
        log.Printf("Install location matched to: %s (%s)", normalized, identifier)
        return identifier
    }

    log.Printf("Using custom install location: %s", normalized)
    return normalized
}

// readBuildInfo loads and parses build-info.yaml from the given directory.
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

// parseVersion converts version strings to a normalized format.
func parseVersion(versionStr string) (string, error) {
    parts := strings.Split(versionStr, ".")
    var numericParts []string

    // Convert all parts to strings to preserve the original input, ensuring they're valid numbers.
    for _, part := range parts {
        if _, err := strconv.Atoi(part); err != nil {
            return "", fmt.Errorf("invalid version part: %q is not a number", part)
        }
        numericParts = append(numericParts, part)
    }

    // Join the parts back together to form the version string.
    return strings.Join(numericParts, "."), nil
}

// createProjectDirectory ensures necessary project directories exist.
func createProjectDirectory(projectDir string) error {
    subDirs := []string{
        "payload",
        "scripts",
        "build",
    }

    for _, subDir := range subDirs {
        fullPath := filepath.Join(projectDir, subDir)
        if err := os.MkdirAll(fullPath, os.ModePerm); err != nil {
            return fmt.Errorf("failed to create directory %s: %w", fullPath, err)
        }
    }
    return nil
}

// handlePostInstallScript manages the postinstall.ps1 file.
func handlePostInstallScript(action, projectDir string) error {
    postInstallPath := filepath.Join(projectDir, "scripts", "postinstall.ps1")
    var command string

    // Determine the command based on the action
    switch action {
    case "logout":
        command = "shutdown /l\n"
    case "restart":
        command = "shutdown /r /t 0\n"
    case "none":
        log.Println("No post-install action required.")
        return nil // No further action needed
    default:
        return fmt.Errorf("unknown post-install action: %s", action)
    }

    // Check if postinstall.ps1 exists and handle appropriately
    var file *os.File
    if _, err := os.Stat(postInstallPath); os.IsNotExist(err) {
        // Create a new postinstall.ps1 file
        log.Printf("Creating new postinstall.ps1: %s", postInstallPath)
        if err := os.MkdirAll(filepath.Dir(postInstallPath), os.ModePerm); err != nil {
            return fmt.Errorf("failed to create scripts directory: %v", err)
        }
        file, err = os.Create(postInstallPath)
        if err != nil {
            return fmt.Errorf("failed to create postinstall.ps1: %v", err)
        }
    } else {
        // Append to the existing postinstall.ps1 file
        log.Printf("Appending to existing postinstall.ps1: %s", postInstallPath)
        file, err = os.OpenFile(postInstallPath, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
        if err != nil {
            return fmt.Errorf("failed to open postinstall.ps1: %v", err)
        }
    }
    defer file.Close()

    // Write or append the command
    if _, err := file.WriteString(command); err != nil {
        return fmt.Errorf("failed to write to postinstall.ps1: %v", err)
    }

    log.Printf("Post-install command added: %s", command)
    return nil
}

// generateNuspec creates a .nuspec file, resolving install locations flexibly.
func generateNuspec(buildInfo *BuildInfo, projectDir string) (string, error) {
    // Fetch standard Windows directories (if applicable).
    dirs := getStandardDirectories()

    nuspecPath := filepath.Join(projectDir, "build", buildInfo.Product.Name+".nuspec")

    // Define the package metadata.
    nuspec := Package{
        Metadata: Metadata{
            ID:          buildInfo.Product.Identifier,
            Version:     buildInfo.Product.Version,
            Authors:     buildInfo.Product.Publisher,
            Description: fmt.Sprintf("%s installer package.", buildInfo.Product.Name),
            Tags:        "admin",
        },
    }

    // Add all payload files recursively.
    payloadPath := filepath.Join(projectDir, "payload")
    if _, err := os.Stat(payloadPath); !os.IsNotExist(err) {
        err := filepath.Walk(payloadPath, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            if !info.IsDir() {
                relPath, err := filepath.Rel(projectDir, path)
                if err != nil {
                    return err
                }
                nuspec.Files = append(nuspec.Files, FileRef{
                    Src:    relPath,
                    Target: filepath.Base(relPath),
                })
            }
            return nil
        })
        if err != nil {
            return "", fmt.Errorf("error walking the payload directory: %w", err)
        }
    }

    // Add preinstall and postinstall scripts if they exist.
    addScriptIfExists(&nuspec, projectDir, "preinstall.ps1", "tools/chocolateyBeforeModify.ps1")
    addScriptIfExists(&nuspec, projectDir, "postinstall.ps1", "tools/chocolateyInstall.ps1")

    // Write the .nuspec file.
    file, err := os.Create(nuspecPath)
    if err != nil {
        return "", fmt.Errorf("failed to create .nuspec file: %w", err)
    }
    defer file.Close()

    // Create an XML encoder and format the output.
    encoder := xml.NewEncoder(file)
    encoder.Indent("", "  ")

    // Encode the package structure.
    if err := encoder.Encode(nuspec); err != nil {
        return "", fmt.Errorf("failed to encode .nuspec: %w", err)
    }

    return nuspecPath, nil
}

// addScriptIfExists checks if a script exists and adds it to the .nuspec files list.
func addScriptIfExists(nuspec *Package, projectDir, scriptName, targetPath string) {
    scriptPath := filepath.Join(projectDir, "scripts", scriptName)
    if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
        nuspec.Files = append(nuspec.Files, FileRef{
            Src:    filepath.Join("scripts", scriptName),
            Target: targetPath,
        })
    }
}

// runCommand executes shell commands with logging.
func runCommand(command string, args ...string) error {
    log.Printf("Running: %s %v", command, args)
    cmd := exec.Command(command, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

// signPackage signs the .nupkg using SignTool.
func signPackage(nupkgFile, certificate string) error {
    log.Printf("Signing package: %s with certificate: %s", nupkgFile, certificate)
    return runCommand(
        "signtool", "sign", "/n", certificate,
        "/fd", "SHA256", "/tr", "http://timestamp.digicert.com",
        "/td", "SHA256", nupkgFile,
    )
}

// check nuget is installed
func checkNuGet() {
    if err := runCommand("nuget", "locals", "all", "-list"); err != nil {
        log.Fatalf(`NuGet is not installed or not in PATH. 
You can install it via Chocolatey: 
  choco install nuget.commandline`)
    }
}

// check signtool is installed
func checkSignTool() {
    if err := runCommand("signtool", "-?"); err != nil {
        log.Fatalf("SignTool is not installed or not available: %v", err)
    }
}

// main is the entry point of the application.
func main() {
    var verbose bool

    // Ensure the project directory is provided as the first command-line argument.
    if len(os.Args) < 2 {
        log.Fatalf("Usage: %s <project_directory>", os.Args[0])
    }
    projectDir := NormalizePath(os.Args[1])

    // Parse any additional flags.
    flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
    flag.Parse()

    setupLogging(verbose)

    log.Printf("Using project directory: %s", projectDir)

    // Verify the project structure exists and is valid.
    if err := verifyProjectStructure(projectDir); err != nil {
        log.Fatalf("Error verifying project structure: %v", err)
    }
    log.Println("Project structure verified. Proceeding with package creation...")

    // Read build-info.yaml from the provided project directory.
    buildInfo, err := readBuildInfo(projectDir)
    if err != nil {
        log.Fatalf("Error reading build-info.yaml: %v", err)
    }

    // If postinstall_action is present, handle it.
    if buildInfo.PostInstallAction != "" {
        validActions := map[string]bool{"none": true, "logout": true, "restart": true}
        if !validActions[buildInfo.PostInstallAction] {
            log.Fatalf("Invalid post-install action: %s", buildInfo.PostInstallAction)
        }

        if err := handlePostInstallScript(buildInfo.PostInstallAction, projectDir); err != nil {
            log.Fatalf("Error handling post-install script: %v", err)
        }
    } else {
        log.Println("No post-install action required.")
    }

    // Create the required directories inside the project.
    if err := createProjectDirectory(projectDir); err != nil {
        log.Fatalf("Error creating directories: %v", err)
    }
    log.Println("Directories created successfully.")

    // Generate the .nuspec file and defer its removal after use.
    nuspecPath, err := generateNuspec(buildInfo, projectDir)
    if err != nil {
        log.Fatalf("Error generating .nuspec: %v", err)
    }
    defer os.Remove(nuspecPath)
    log.Printf(".nuspec generated at: %s", nuspecPath)

    // Ensure NuGet is available for packaging.
    checkNuGet()

    // Set up paths for the build directory and final .nupkg output.
    buildDir := filepath.Join(projectDir, "build")
    nupkgPath := filepath.Join(buildDir, buildInfo.Product.Name+".nupkg")

    // Run NuGet to pack the package.
    if err := runCommand("nuget", "pack", nuspecPath, "-OutputDirectory", buildDir); err != nil {
        log.Fatalf("Error creating package: %v", err)
    }

    // Check if signing is required, and sign the package if a certificate is provided.
    if buildInfo.SigningCertificate != "" {
        checkSignTool()
        if err := signPackage(nupkgPath, buildInfo.SigningCertificate); err != nil {
            log.Fatalf("Failed to sign package %s: %v", nupkgPath, err)
        }
    } else {
        log.Println("No signing certificate provided. Skipping signing.")
    }

    log.Printf("Package created successfully: %s", nupkgPath)
}
