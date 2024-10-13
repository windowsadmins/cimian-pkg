package main

import (
    "encoding/xml"
    "flag"
    "fmt"
    "gopkg.in/yaml.v2"
    "io/ioutil"
    "log"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
)

// Structs for YAML and XML parsing

type BuildInfo struct {
    Product struct {
        Name         string `yaml:"name"`
        Version      string `yaml:"version"`
        Manufacturer string `yaml:"manufacturer"`
    } `yaml:"product"`
    InstallPath string `yaml:"install_path"`
}

type Package struct {
    XMLName  xml.Name  `xml:"package"`
    Metadata Metadata  `xml:"metadata"`
    Files    []FileRef `xml:"files>file"`
}

type Metadata struct {
    ID          string `xml:"id"`
    Version     string `xml:"version"`
    Authors     string `xml:"authors"`
    Description string `xml:"description"`
}

type FileRef struct {
    Src    string `xml:"src,attr"`
    Target string `xml:"target,attr"`
}

// Setup logging based on verbosity
func setupLogging(verbose bool) {
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    if verbose {
        log.SetOutput(os.Stdout)
    } else {
        log.SetOutput(os.Stderr)
    }
}

// Read and parse the build-info.yaml file
func readBuildInfo(projectDir string) (*BuildInfo, error) {
    data, err := ioutil.ReadFile(filepath.Join(projectDir, "build-info.yaml"))
    if err != nil {
        return nil, err
    }

    var buildInfo BuildInfo
    err = yaml.Unmarshal(data, &buildInfo)
    if err != nil {
        return nil, err
    }

    return &buildInfo, nil
}

// parseVersion handles different version formats:
// 1. Date-based versions: "YYYY.MM.DD"
// 2. Semantic versions: "X.Y.Z" or "X.Y.Z.B"
func parseVersion(versionStr string) (string, error) {
    parts := strings.Split(versionStr, ".")
    
    var major, minor, build int
    var err error

    switch len(parts) {
    case 3: // Possible date-based version (e.g., "2024.10.12") or semantic version "X.Y.Z"
        if len(parts[0]) == 4 { // Date-based version
            major, err = strconv.Atoi(parts[0][2:]) // Take the last two digits of the year
            if err != nil {
                return "", fmt.Errorf("invalid year: %v", err)
            }
        } else { // Semantic version
            major, err = strconv.Atoi(parts[0])
            if err != nil {
                return "", fmt.Errorf("invalid major version: %v", err)
            }
        }
        minor, err = strconv.Atoi(parts[1])
        if err != nil {
            return "", fmt.Errorf("invalid minor version: %v", err)
        }
        build, err = strconv.Atoi(parts[2])
        if err != nil {
            return "", fmt.Errorf("invalid build version: %v", err)
        }

    case 4: // Semantic version with build number (e.g., "1.2.3.456")
        major, err = strconv.Atoi(parts[0])
        if err != nil {
            return "", fmt.Errorf("invalid major version: %v", err)
        }
        minor, err = strconv.Atoi(parts[1])
        if err != nil {
            return "", fmt.Errorf("invalid minor version: %v", err)
        }
        build, err = strconv.Atoi(parts[2])
        if err != nil {
            return "", fmt.Errorf("invalid build version: %v", err)
        }
        extra, err := strconv.Atoi(parts[3])
        if err != nil {
            return "", fmt.Errorf("invalid extra build number: %v", err)
        }
        build = (build * 1000) + extra

    default:
        return "", fmt.Errorf("invalid version format: %s", versionStr)
    }

    // Ensure minor and build numbers fit within their ranges.
    minor = minor % 256
    build = build % 65536

    return fmt.Sprintf("%d.%d.%d", major, minor, build), nil
}

// Create necessary directories (payload and scripts)
func createProjectDirectory(projectDir string) error {
    paths := []string{
        filepath.Join(projectDir, "payload"),
        filepath.Join(projectDir, "scripts"),
    }
    for _, path := range paths {
        if err := os.MkdirAll(path, os.ModePerm); err != nil {
            return err
        }
    }
    return nil
}

// Generate the .nuspec XML file based on available files and scripts.
func generateNuspec(buildInfo *BuildInfo) error {
    var files []FileRef

    // Check if the payload directory exists and add it.
    payloadPath := "payload\\**"
    if _, err := os.Stat("payload"); err == nil {
        files = append(files, FileRef{Src: payloadPath, Target: buildInfo.InstallPath})
    } else {
        log.Println("No payload found. Skipping payload packaging.")
    }

    // Check if preinstall.ps1 exists and map to tools/install.ps1.
    if _, err := os.Stat("scripts/preinstall.ps1"); err == nil {
        files = append(files, FileRef{
            Src:    "scripts\\preinstall.ps1",
            Target: "tools\\install.ps1",
        })
    } else {
        log.Println("No preinstall.ps1 script found.")
    }

    // Check if postinstall.ps1 exists and map to tools/chocolateyInstall.ps1.
    if _, err := os.Stat("scripts/postinstall.ps1"); err == nil {
        files = append(files, FileRef{
            Src:    "scripts\\postinstall.ps1",
            Target: "tools\\chocolateyInstall.ps1",
        })
    } else {
        log.Println("No postinstall.ps1 script found.")
    }

    // Define the .nuspec metadata and package structure.
    nuspec := Package{
        Metadata: Metadata{
            ID:          buildInfo.Product.Name,
            Version:     buildInfo.Product.Version,
            Authors:     buildInfo.Product.Manufacturer,
            Description: fmt.Sprintf("%s installer package.", buildInfo.Product.Name),
        },
        Files: files,
    }

    // Write the .nuspec file.
    file, err := os.Create(buildInfo.Product.Name + ".nuspec")
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := xml.NewEncoder(file)
    encoder.Indent("", "  ")
    return encoder.Encode(nuspec)
}

// Execute shell commands (e.g., nuget pack)
func runCommand(command string, args ...string) error {
    cmd := exec.Command(command, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    log.Printf("Running command: %s %v", command, args)
    return cmd.Run()
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

// Execute post-install actions based on user configuration
func handlePostInstallAction(action string) {
    var cmd *exec.Cmd

    switch action {
    case "logout":
        log.Println("Logging out...")
        cmd = exec.Command("shutdown", "/l")
    case "restart":
        log.Println("Restarting system...")
        cmd = exec.Command("shutdown", "/r", "/t", "0")
    case "none":
        log.Println("No post-install action specified.")
        return // No further action needed.
    default:
        log.Printf("Unknown post-install action: %s", action)
        return // Exit if an unknown action is provided.
    }

    // Run the command and handle potential errors.
    if err := cmd.Run(); err != nil {
        log.Printf("Failed to execute %s action: %v", action, err)
    } else {
        log.Printf("%s action executed successfully.", action)
    }
}

// Main function
func main() {
    var projectDir string
    var verbose bool

    flag.StringVar(&projectDir, "project", ".", "The project directory to build.")
    flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging.")
    flag.Parse()

    setupLogging(verbose)

    buildInfo, err := readBuildInfo(projectDir)
    if err != nil {
        log.Fatalf("Failed to read build-info.yaml: %v", err)
    }

    version, err := parseVersion(buildInfo.Product.Version)
    if err != nil {
        log.Fatalf("Invalid version format: %v", err)
    }
    log.Printf("Parsed version: %s", version)

    if err := createProjectDirectory(projectDir); err != nil {
        log.Fatalf("Failed to create project directory: %v", err)
    }

    if err := generateNuspec(buildInfo); err != nil {
        log.Fatalf("Failed to generate .nuspec file: %v", err)
    }

    if err := runCommand("nuget", "pack", buildInfo.Product.Name+".nuspec"); err != nil {
        log.Fatalf("Failed to run nuget pack: %v", err)
    }

    log.Println("Package created successfully.")
}
