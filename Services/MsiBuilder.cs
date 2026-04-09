using System.Diagnostics;
using System.Text;
using Cimian.CLI.Cimipkg.Models;
using Microsoft.Extensions.Logging;
using WixToolset.Dtf.WindowsInstaller;
using YamlDotNet.Serialization;

namespace Cimian.CLI.Cimipkg.Services;

/// <summary>
/// Builds Windows Installer (.msi) packages directly using DTF,
/// bypassing the WiX compiler entirely. Supports payload, scripts, or both.
/// </summary>
public class MsiBuilder
{
    private readonly ILogger _logger;
    private readonly CodeSigner _codeSigner;
    private readonly ScriptProcessor _scriptProcessor;
    private readonly ISerializer _yamlSerializer;

    // Standard MSI sequence numbers for InstallExecuteSequence
    private const int SeqLaunchConditions = 100;
    private const int SeqFindRelatedProducts = 200;
    private const int SeqRemoveExistingProducts = 1525;
    private const int SeqPreinstallScript = 3900;
    private const int SeqInstallFiles = 4000;
    private const int SeqPostinstallScript = 4100;
    private const int SeqInstallFinalize = 6600;

    public MsiBuilder(
        ILogger logger,
        CodeSigner codeSigner,
        ScriptProcessor scriptProcessor,
        ISerializer yamlSerializer)
    {
        _logger = logger;
        _codeSigner = codeSigner;
        _scriptProcessor = scriptProcessor;
        _yamlSerializer = yamlSerializer;
    }

    /// <summary>
    /// Build an MSI package from the project directory.
    /// </summary>
    public string Build(
        BuildInfo buildInfo,
        string projectDir,
        string originalVersion,
        bool hasPayloadFiles,
        Dictionary<string, string> envVars)
    {
        var productName = buildInfo.Product.Name;
        var identifier = buildInfo.Product.Identifier;

        // Generate MSI version
        var (msiVersion, fullVersion) = MsiVersionConverter.Convert(buildInfo.Product.Version);
        _logger.LogInformation("MSI version: {MsiVersion} (full: {FullVersion})", msiVersion, fullVersion);

        // Generate GUIDs
        var productCode = UpgradeCodeGenerator.GenerateProductCode();
        var upgradeCode = !string.IsNullOrEmpty(buildInfo.UpgradeCode)
            ? Guid.Parse(buildInfo.UpgradeCode)
            : UpgradeCodeGenerator.GenerateUpgradeCode(identifier);

        _logger.LogInformation("ProductCode: {ProductCode}", productCode);
        _logger.LogInformation("UpgradeCode: {UpgradeCode}", upgradeCode);

        // Collect payload files
        var payloadDir = Path.Combine(projectDir, "payload");
        var payloadFiles = hasPayloadFiles
            ? Directory.GetFiles(payloadDir, "*", SearchOption.AllDirectories)
            : [];

        // Collect scripts
        var scriptsDir = Path.Combine(projectDir, "scripts");
        var hasScripts = Directory.Exists(scriptsDir) &&
            Directory.GetFiles(scriptsDir, "*.ps1").Length > 0;

        // Serialize build-info.yaml for embedding
        var buildInfoYaml = _yamlSerializer.Serialize(buildInfo);

        // Build output path
        var buildDir = Path.Combine(projectDir, "build");
        Directory.CreateDirectory(buildDir);
        var msiFileName = $"{productName}-{buildInfo.Product.Version}.msi";
        var msiPath = Path.Combine(buildDir, msiFileName);

        // Delete existing MSI if present
        if (File.Exists(msiPath))
            File.Delete(msiPath);

        _logger.LogInformation("Creating MSI: {MsiPath}", msiPath);

        // Create the MSI database
        using (var db = new Database(msiPath, DatabaseOpenMode.Create))
        {
            _logger.LogDebug("Creating tables...");
            CreateTables(db);

            _logger.LogDebug("Writing properties...");
            WriteProperties(db, productName, msiVersion, fullVersion, identifier,
                productCode, upgradeCode, buildInfo, buildInfoYaml);

            _logger.LogDebug("Writing directory table...");
            var isInstallerType = string.IsNullOrWhiteSpace(buildInfo.InstallLocation);
            WriteDirectoryTable(db, buildInfo.InstallLocation, isInstallerType, productName);

            // For scripts: installDir is where MSI puts files. For installer-type, this is
            // TempFolder\p_{guid} (resolved at install time). For copy-type, it's the actual path.
            var installDir = isInstallerType
                ? "[INSTALLDIR]"  // placeholder — actual path resolved at install time
                : buildInfo.InstallLocation!.TrimEnd('\\', '/');


            _logger.LogDebug("Writing upgrade table...");
            WriteUpgradeTable(db, upgradeCode);

            if (payloadFiles.Length > 0)
            {
                _logger.LogDebug("Writing payload tables ({Count} files)...", payloadFiles.Length);
                WritePayloadTables(db, payloadDir, payloadFiles, identifier);
            }
            else
            {
                WriteEmptyFeature(db);
            }

            _logger.LogDebug("Writing install sequence...");
            WriteInstallSequence(db, hasScripts, hasPayloadFiles);

            if (hasScripts)
            {
                _logger.LogDebug("Writing script custom actions...");
                WriteScriptCustomActions(db, scriptsDir, envVars, installDir);
            }

            _logger.LogDebug("Committing database...");
            db.Commit();
        }

        // Write Summary Information Stream after database is closed
        WriteSummaryInfo(msiPath, productName, msiVersion, buildInfo);

        // Embed payload files as a CAB archive inside the MSI
        if (payloadFiles.Length > 0)
        {
            _logger.LogInformation("Creating and embedding CAB archive ({Count} files)...", payloadFiles.Length);
            EmbedPayloadCab(msiPath, payloadDir, payloadFiles);
        }

        _logger.LogInformation("MSI database created successfully");

        // Sign the MSI if certificate is configured
        // SignPowerShellScript uses signtool.exe which works for any Authenticode-signable file
        if (!string.IsNullOrEmpty(buildInfo.SigningCertificate) ||
            !string.IsNullOrEmpty(buildInfo.SigningThumbprint))
        {
            _logger.LogInformation("Signing MSI...");
            _codeSigner.SignPowerShellScript(msiPath,
                buildInfo.SigningCertificate, buildInfo.SigningThumbprint);
        }

        return msiPath;
    }

    private static void CreateTables(Database db)
    {
        // Property table
        db.Execute("CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR LOCALIZABLE PRIMARY KEY `Property`)");

        // Directory table
        db.Execute("CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, `Directory_Parent` CHAR(72), `DefaultDir` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Directory`)");

        // Component table
        db.Execute("CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), `Directory_` CHAR(72) NOT NULL, `Attributes` SHORT NOT NULL, `Condition` CHAR(255), `KeyPath` CHAR(72) PRIMARY KEY `Component`)");

        // File table
        db.Execute("CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `FileSize` LONG NOT NULL, `Version` CHAR(72), `Language` CHAR(20), `Attributes` SHORT, `Sequence` SHORT NOT NULL PRIMARY KEY `File`)");

        // Media table
        db.Execute("CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` SHORT NOT NULL, `DiskPrompt` CHAR(64) LOCALIZABLE, `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), `Source` CHAR(72) PRIMARY KEY `DiskId`)");

        // Feature table
        db.Execute("CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), `Title` CHAR(64) LOCALIZABLE, `Description` CHAR(255) LOCALIZABLE, `Display` SHORT, `Level` SHORT NOT NULL, `Directory_` CHAR(72), `Attributes` SHORT NOT NULL PRIMARY KEY `Feature`)");

        // FeatureComponents table
        db.Execute("CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)");

        // CustomAction table
        db.Execute("CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` LONGCHAR, `ExtendedType` LONG PRIMARY KEY `Action`)");

        // InstallExecuteSequence table
        db.Execute("CREATE TABLE `InstallExecuteSequence` (`Action` CHAR(72) NOT NULL, `Condition` CHAR(255), `Sequence` SHORT PRIMARY KEY `Action`)");

        // Upgrade table
        db.Execute("CREATE TABLE `Upgrade` (`UpgradeCode` CHAR(38) NOT NULL, `VersionMin` CHAR(20), `VersionMax` CHAR(20), `Language` CHAR(255), `Attributes` LONG NOT NULL, `Remove` CHAR(255), `ActionProperty` CHAR(72) NOT NULL PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`)");
    }

    private static void WriteSummaryInfo(string msiPath, string productName, string msiVersion, BuildInfo buildInfo)
    {
        using var si = new SummaryInfo(msiPath, enableWrite: true);
        si.Title = "Installation Database";
        si.Subject = productName;
        si.Author = buildInfo.Product.Developer ?? "Cimian";
        si.Comments = buildInfo.Product.Description ?? $"{productName} installer";
        si.Template = "x64;1033"; // x64 platform, English
        si.RevisionNumber = $"{{{Guid.NewGuid()}}}"; // Package code (unique per MSI file)
        si.CreatingApp = "cimipkg";
        si.PageCount = 200; // Minimum installer version (2.0)
        si.WordCount = 2; // Bit 1 = compressed source files (CAB embedded)
        si.Security = 2; // Read-only recommended
        si.Persist();
    }

    private static void WriteProperties(
        Database db,
        string productName,
        string msiVersion,
        string fullVersion,
        string identifier,
        Guid productCode,
        Guid upgradeCode,
        BuildInfo buildInfo,
        string buildInfoYaml)
    {
        void SetProperty(string name, string value)
        {
            try
            {
                var sql = $"INSERT INTO `Property` (`Property`, `Value`) VALUES ('{EscSql(name)}', '{EscSql(value)}')";
                db.Execute(sql);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Failed to set property '{name}' (value length={value.Length}): {ex.Message}", ex);
            }
        }

        // Standard MSI properties
        SetProperty("ProductName", productName);
        SetProperty("ProductVersion", msiVersion);
        SetProperty("ProductCode", $"{{{productCode}}}");
        SetProperty("UpgradeCode", $"{{{upgradeCode}}}");
        SetProperty("Manufacturer", buildInfo.Product.Developer ?? "Unknown");
        SetProperty("ProductLanguage", "1033");
        SetProperty("ALLUSERS", "1");
        SetProperty("ARPNOREPAIR", "1");
        SetProperty("ARPNOMODIFY", "1");
        SetProperty("MSIFASTINSTALL", "7");
        SetProperty("MsiLogging", "voicewarmup");

        // Suppress reboots
        SetProperty("REBOOT", "ReallySuppress");
        SetProperty("MSIRESTARTMANAGERCONTROL", "Disable");

        // ARP (Add/Remove Programs) properties
        if (!string.IsNullOrEmpty(buildInfo.Product.Description))
            SetProperty("ARPCOMMENTS", buildInfo.Product.Description);
        if (!string.IsNullOrEmpty(buildInfo.Product.Url))
            SetProperty("ARPURLINFOABOUT", buildInfo.Product.Url);

        // Cimian-specific properties
        SetProperty("CIMIAN_IDENTIFIER", identifier);
        SetProperty("CIMIAN_FULL_VERSION", fullVersion);
        SetProperty("CIMIAN_PKG_BUILD_INFO", buildInfoYaml);

        // Upgrade-related
        SetProperty("PREVIOUSVERSIONSINSTALLED", "");
        SetProperty("SecureCustomProperties", "PREVIOUSVERSIONSINSTALLED");

        // Custom MSI properties from build-info.yaml
        if (buildInfo.MsiProperties != null)
        {
            foreach (var (key, value) in buildInfo.MsiProperties)
            {
                SetProperty(key, value);
            }
        }
    }

    private static void WriteDirectoryTable(Database db, string installLocation, bool isInstallerType, string productName)
    {
        db.Execute("INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('TARGETDIR', '', 'SourceDir')");

        if (isInstallerType)
        {
            // Installer-type packages: use MSI's TempFolder (resolves at install time to
            // the SYSTEM temp dir when running elevated). Same pattern as sbin-installer
            // extracting .pkg to %TEMP%\p_{guid}. Files are staged here temporarily —
            // the postinstall runs the inner installer, then cleanup happens naturally.
            var tempSubDir = $"p_{Guid.NewGuid():N}";
            db.Execute("INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('TempFolder', 'TARGETDIR', '.')");
            db.Execute($"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('INSTALLDIR', 'TempFolder', '{EscSql(tempSubDir)}')");
            return;
        }

        // Copy-type packages: resolve install_location to a well-known MSI system folder
        var cleanPath = installLocation!.TrimEnd('\\', '/');
        var progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        string parentDirId;
        string subPath;

        if (cleanPath.StartsWith(progFiles, StringComparison.OrdinalIgnoreCase))
        {
            parentDirId = "ProgramFiles64Folder";
            subPath = cleanPath[progFiles.Length..].TrimStart('\\', '/');
        }
        else if (cleanPath.StartsWith(commonAppData, StringComparison.OrdinalIgnoreCase))
        {
            parentDirId = "CommonAppDataFolder";
            subPath = cleanPath[commonAppData.Length..].TrimStart('\\', '/');
        }
        else
        {
            parentDirId = "ProgramFiles64Folder";
            subPath = Path.GetFileName(cleanPath);
            if (string.IsNullOrEmpty(subPath)) subPath = "Install";
        }

        db.Execute($"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('{parentDirId}', 'TARGETDIR', '.')");

        // Each path segment is a separate directory entry (MSI DefaultDir can't contain backslashes)
        var segments = subPath.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
        var currentParent = parentDirId;

        for (int i = 0; i < segments.Length; i++)
        {
            var isLast = i == segments.Length - 1;
            var dirId = isLast ? "INSTALLDIR" : $"D_{SanitizeIdentifier(string.Join("_", segments[..(i + 1)]))}";
            db.Execute($"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('{EscSql(dirId)}', '{EscSql(currentParent)}', '{EscSql(segments[i])}')");
            currentParent = dirId;
        }
    }

    private static void WriteUpgradeTable(Database db, Guid upgradeCode)
    {
        var uc = EscSql($"{{{upgradeCode}}}");
        db.Execute($"INSERT INTO `Upgrade` (`UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`, `Remove`, `ActionProperty`) VALUES ('{uc}', '0.0.0', '', '', 256, '', 'PREVIOUSVERSIONSINSTALLED')");
    }

    private void WritePayloadTables(
        Database db,
        string payloadDir,
        string[] payloadFiles,
        string identifier)
    {
        // Single media entry with embedded CAB (#product.cab = embedded stream)
        db.Execute($"INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES (1, {payloadFiles.Length}, '', '#product.cab', '', '')");

        // Single feature
        db.Execute(
            "INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes`) VALUES ('DefaultFeature', '', 'Complete', 'Full installation', 1, 1, 'INSTALLDIR', 0)");

        int sequence = 1;
        foreach (var filePath in payloadFiles)
        {
            var relativePath = Path.GetRelativePath(payloadDir, filePath).Replace('\\', '/');
            var fileName = Path.GetFileName(filePath);
            var fileSize = new FileInfo(filePath).Length;

            // Generate deterministic component ID
            var componentId = UpgradeCodeGenerator.GenerateComponentId(identifier, relativePath);
            var componentKey = $"C_{SanitizeIdentifier(relativePath)}";
            var fileKey = $"F_{SanitizeIdentifier(relativePath)}";

            // Ensure keys fit within 72-char MSI limit
            if (componentKey.Length > 72)
                componentKey = $"C_{componentId:N}"[..72];
            if (fileKey.Length > 72)
                fileKey = $"F_{componentId:N}"[..72];

            // Determine directory for subdirectories in payload
            var subDir = Path.GetDirectoryName(relativePath)?.Replace('/', '\\');
            var directoryRef = "INSTALLDIR";
            if (!string.IsNullOrEmpty(subDir))
            {
                var dirKey = $"D_{SanitizeIdentifier(subDir)}";
                if (dirKey.Length > 72)
                    dirKey = $"D_{Guid.NewGuid():N}"[..72];

                // Create subdirectory entry if not exists
                try
                {
                    db.Execute($"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('{EscSql(dirKey)}', 'INSTALLDIR', '{EscSql(subDir.Replace('\\', '|'))}')");

                }
                catch
                {
                    // Directory already exists
                }

                directoryRef = dirKey;
            }

            // MSI FileName format: "ShortName|LongName"
            var shortName = GenerateShortName(fileName, sequence);
            var msiFileName = $"{shortName}|{fileName}";

            // Component: Attributes=256 means 64-bit component
            var cid = EscSql($"{{{componentId}}}");
            db.Execute($"INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath`) VALUES ('{EscSql(componentKey)}', '{cid}', '{EscSql(directoryRef)}', 256, '', '{EscSql(fileKey)}')");

            // Extract PE FileVersion so Windows Installer's file versioning rules work.
            // Without this, the File table Version column is empty and MSI treats the payload
            // as "unversioned", which means it will refuse to overwrite a versioned file
            // already on disk — the install "succeeds" but silently skips the file copy.
            // Leave empty for truly unversioned files (scripts, txt, etc.).
            var fileVersion = "";
            try
            {
                var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
                var major = vi.FileMajorPart;
                var minor = vi.FileMinorPart;
                var build = vi.FileBuildPart;
                var revision = vi.FilePrivatePart;
                if (major > 0 || minor > 0 || build > 0 || revision > 0)
                {
                    // MSI requires each version part to be 0-65535
                    fileVersion = $"{Math.Min(major, 65535)}.{Math.Min(minor, 65535)}.{Math.Min(build, 65535)}.{Math.Min(revision, 65535)}";
                }
            }
            catch
            {
                // Unversioned file — fall back to empty, MSI will compare by modification time
            }

            // File
            db.Execute($"INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence`) VALUES ('{EscSql(fileKey)}', '{EscSql(componentKey)}', '{EscSql(msiFileName)}', {fileSize}, '{EscSql(fileVersion)}', '', 0, {sequence})");

            // FeatureComponents
            db.Execute($"INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('DefaultFeature', '{EscSql(componentKey)}')");


            _logger.LogDebug("Added file: {RelativePath} ({Size} bytes)", relativePath, fileSize);
            sequence++;
        }
    }

    private static void WriteEmptyFeature(Database db)
    {
        db.Execute(
            "INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes`) VALUES ('DefaultFeature', '', 'Complete', 'Full installation', 1, 1, 'INSTALLDIR', 0)");

        // Media table still needed even with no files
        db.Execute(
            "INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES (1, 0, '', '', '', '')");

        // Need a Registry table for the marker component
        db.Execute(
            "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL LOCALIZABLE, `Name` CHAR(255) LOCALIZABLE, `Value` LONGCHAR LOCALIZABLE, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)");

        // Dummy registry component so MSI has something to "install" and runs the full sequence.
        // Without this, scripts-only packages get short-circuited by Windows Installer.
        var componentId = $"{{{Guid.NewGuid()}}}";
        db.Execute($"INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath`) VALUES ('C_CimianMarker', '{EscSql(componentId)}', 'INSTALLDIR', 260, '', 'R_CimianMarker')");

        // Registry entry: HKLM\SOFTWARE\Cimian\Packages\{identifier} = installed
        // Root=2 means HKLM
        db.Execute("INSERT INTO `Registry` (`Registry`, `Root`, `Key`, `Name`, `Value`, `Component_`) VALUES ('R_CimianMarker', 2, 'SOFTWARE\\Cimian\\Packages', 'ScriptPackage', '1', 'C_CimianMarker')");

        db.Execute("INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('DefaultFeature', 'C_CimianMarker')");
    }

    private static void WriteInstallSequence(Database db, bool hasScripts, bool hasPayload)
    {
        void AddAction(string action, string? condition, int sequence)
        {
            db.Execute($"INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ('{EscSql(action)}', '{EscSql(condition ?? "")}', {sequence})");
        }

        // Full standard install sequence — all required actions for a working MSI
        AddAction("LaunchConditions", null, 100);
        AddAction("FindRelatedProducts", null, 200);
        AddAction("AppSearch", null, 400);
        AddAction("CostInitialize", null, 800);
        AddAction("FileCost", null, 900);
        AddAction("CostFinalize", null, 1000);
        AddAction("InstallValidate", null, 1400);
        AddAction("InstallInitialize", null, 1500);
        AddAction("RemoveExistingProducts", null, 1525);
        AddAction("ProcessComponents", null, 1600);
        AddAction("UnpublishFeatures", null, 1800);

        if (hasScripts)
        {
            // Preinstall: immediate — runs before InstallInitialize, stops services/processes.
            // Condition: runs on fresh install and major upgrade, but NOT standalone uninstall.
            AddAction("CimianPreinstall", "NOT (REMOVE=\"ALL\")", 1498);
        }

        if (hasPayload)
        {
            AddAction("RemoveFiles", null, 3500);
            AddAction("InstallFiles", null, 4000);
        }

        AddAction("RegisterUser", null, 6000);
        AddAction("RegisterProduct", null, 6100);
        AddAction("PublishFeatures", null, 6300);
        AddAction("PublishProduct", null, 6400);
        AddAction("InstallFinalize", null, 6600);

        if (hasScripts)
        {
            // Postinstall: immediate AFTER InstallFinalize — all files on disk.
            // Condition: NOT a standalone uninstall. Runs on fresh install AND major upgrade.
            AddAction("CimianPostinstall", "NOT (REMOVE=\"ALL\")", 6601);
            // Uninstall: runs ONLY during standalone uninstall (not during major upgrade removal)
            AddAction("CimianUninstall", "REMOVE=\"ALL\"", 6602);
        }
    }

    private void WriteScriptCustomActions(
        Database db,
        string scriptsDir,
        Dictionary<string, string> envVars,
        string installDir)
    {
        // Inject $payloadRoot so scripts can find staged files — matching sbin-installer behavior.
        // For installer-type (TempFolder), we can't hardcode the path — it resolves at install time.
        // So we inject PowerShell code that reads INSTALLDIR from the MSI property at runtime.
        // For copy-type, we hardcode since the path is known at build time.
        string variableHeader;
        if (installDir == "[INSTALLDIR]")
        {
            // Installer-type: VBScript CA sets CIMIAN_INSTALLDIR env var from Session.Property("INSTALLDIR")
            // before launching PowerShell. Same as sbin-installer setting $payloadRoot from extraction dir.
            variableHeader =
                "$payloadRoot = $env:CIMIAN_INSTALLDIR\r\n" +
                "if (-not $payloadRoot) { $payloadRoot = $PWD.Path }\r\n" +
                "$payloadDir = $payloadRoot\r\n" +
                "$installLocation = $payloadRoot\r\n\r\n";
        }
        else
        {
            var cleanInstallDir = installDir.TrimEnd('\\', '/');
            variableHeader = $"$payloadRoot = '{cleanInstallDir}'\r\n" +
                             $"$payloadDir = '{cleanInstallDir}'\r\n" +
                             $"$installLocation = '{cleanInstallDir}'\r\n\r\n";
        }

        var preinstallScripts = Directory.GetFiles(scriptsDir, "preinstall*.ps1")
            .OrderBy(f => f).ToArray();
        var postinstallScripts = Directory.GetFiles(scriptsDir, "postinstall*.ps1")
            .OrderBy(f => f).ToArray();
        var uninstallScripts = Directory.GetFiles(scriptsDir, "uninstall*.ps1")
            .OrderBy(f => f).ToArray();

        // Preinstall: immediate, before InstallInitialize — stops services/processes
        var preScript = preinstallScripts.Length > 0
            ? variableHeader + CombineScripts(preinstallScripts, envVars) : "# No preinstall scripts";
        WriteImmediateScriptAction(db, "CimianPreinstall", preScript);

        // Postinstall: immediate, AFTER InstallFinalize — all files are on disk
        var postScript = postinstallScripts.Length > 0
            ? variableHeader + CombineScripts(postinstallScripts, envVars) : "# No postinstall scripts";
        WriteImmediateScriptAction(db, "CimianPostinstall", postScript);

        // Uninstall: immediate, AFTER InstallFinalize during removal
        var uninstallScript = uninstallScripts.Length > 0
            ? variableHeader + CombineScripts(uninstallScripts, envVars) : "# No uninstall scripts";
        WriteImmediateScriptAction(db, "CimianUninstall", uninstallScript);
    }

    /// <summary>
    /// Write an immediate custom action (Type 98 = EXE from directory, continue on error).
    /// Used for preinstall which runs during the immediate phase.
    /// </summary>
    private static void WriteImmediateScriptAction(Database db, string actionName, string scriptContent)
    {
        var bytes = Encoding.Unicode.GetBytes(scriptContent);
        var encodedCommand = Convert.ToBase64String(bytes);
        var psExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");

        // VBScript CA (Type 102 = 6+32+64, inline VBS, synchronous, continue on error):
        //   1. Reads INSTALLDIR from Session.Property (available to immediate CAs)
        //   2. Sets CIMIAN_INSTALLDIR env var so PowerShell $payloadRoot resolves at runtime
        //   3. Launches PowerShell completely hidden via WScript.Shell.Run(cmd, 0, True)
        var vbs = "Dim ws, env\r\n" +
                  "Set ws = CreateObject(\"WScript.Shell\")\r\n" +
                  "Set env = ws.Environment(\"Process\")\r\n" +
                  "env(\"CIMIAN_INSTALLDIR\") = Session.Property(\"INSTALLDIR\")\r\n" +
                  $"ws.Run \"{psExe} -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                  $"-EncodedCommand {encodedCommand}\", 0, True";

        db.Execute($"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`, `ExtendedType`) VALUES ('{EscSql(actionName)}', 102, '', '{EscSql(vbs)}', 0)");
    }


    private string CombineScripts(string[] scriptFiles, Dictionary<string, string> envVars)
    {
        return _scriptProcessor.CombineScripts(scriptFiles, envVars);
    }

    /// <summary>
    /// Generate an 8.3 short filename for MSI compatibility.
    /// </summary>
    private static string GenerateShortName(string longName, int sequence)
    {
        var nameWithoutExt = Path.GetFileNameWithoutExtension(longName);
        var ext = Path.GetExtension(longName);

        // Take first 6 chars + ~N
        var shortBase = new string(nameWithoutExt
            .Where(c => char.IsLetterOrDigit(c) || c == '_' || c == '-')
            .Take(6)
            .ToArray())
            .ToUpperInvariant();

        if (string.IsNullOrEmpty(shortBase))
            shortBase = "FILE";

        var shortExt = ext.Length > 0
            ? "." + new string(ext[1..].Where(char.IsLetterOrDigit).Take(3).ToArray()).ToUpperInvariant()
            : "";

        return $"{shortBase}~{sequence}{shortExt}";
    }

    /// <summary>
    /// Sanitize a path into a valid MSI identifier.
    /// </summary>
    /// <summary>
    /// Create a CAB file from payload files and embed it inside the MSI as a stream.
    /// The CAB file names must match the File table keys (e.g., F_hello_txt).
    /// </summary>
    private void EmbedPayloadCab(string msiPath, string payloadDir, string[] payloadFiles)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"cimipkg_cab_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            var cabPath = Path.Combine(tempDir, "product.cab");

            // Build a mapping of File table keys to actual file paths
            // Must match what WritePayloadTables generated
            var fileMapping = new List<(string FileKey, string SourcePath)>();
            int sequence = 1;
            foreach (var filePath in payloadFiles)
            {
                var relativePath = Path.GetRelativePath(payloadDir, filePath).Replace('\\', '/');
                var fileKey = $"F_{SanitizeIdentifier(relativePath)}";

                // Match the truncation logic from WritePayloadTables
                var componentId = UpgradeCodeGenerator.GenerateComponentId("", relativePath);
                if (fileKey.Length > 72)
                    fileKey = $"F_{componentId:N}"[..72];

                fileMapping.Add((fileKey, filePath));
                sequence++;
            }

            // Create DDF (Diamond Directive File) for makecab
            var ddfPath = Path.Combine(tempDir, "product.ddf");
            var ddfContent = new StringBuilder();
            ddfContent.AppendLine(".OPTION EXPLICIT");
            ddfContent.AppendLine($".Set CabinetNameTemplate=product.cab");
            ddfContent.AppendLine($".Set DiskDirectoryTemplate={tempDir}");
            ddfContent.AppendLine(".Set Cabinet=on");
            ddfContent.AppendLine(".Set Compress=on");
            ddfContent.AppendLine(".Set CompressionType=MSZIP");
            ddfContent.AppendLine(".Set MaxDiskSize=0");
            ddfContent.AppendLine(".Set RptFileName=nul");
            ddfContent.AppendLine(".Set InfFileName=nul");
            ddfContent.AppendLine(".Set UniqueFiles=off");

            foreach (var (fileKey, sourcePath) in fileMapping)
            {
                // makecab syntax: "sourcePath" "destinationNameInCab"
                ddfContent.AppendLine($"\"{sourcePath}\" \"{fileKey}\"");
            }

            File.WriteAllText(ddfPath, ddfContent.ToString());

            // Run makecab
            var psi = new ProcessStartInfo
            {
                FileName = "makecab.exe",
                Arguments = $"/F \"{ddfPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = tempDir
            };

            using var process = Process.Start(psi)!;
            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"makecab.exe failed (exit {process.ExitCode}): {error}{output}");
            }

            if (!File.Exists(cabPath))
            {
                throw new FileNotFoundException($"CAB file not created at: {cabPath}");
            }

            _logger.LogDebug("CAB created: {CabPath} ({Size:N0} bytes)",
                cabPath, new FileInfo(cabPath).Length);

            // Embed the CAB into the MSI as a stream named "product.cab"
            using var db = new Database(msiPath, DatabaseOpenMode.Direct);

            using var view = db.OpenView(
                "SELECT `Name`, `Data` FROM `_Streams`");
            view.Execute();

            using var record = new Record(2);
            record.SetString(1, "product.cab");
            record.SetStream(2, cabPath);
            view.Modify(ViewModifyMode.Assign, record);

            db.Commit();

            _logger.LogInformation("CAB embedded in MSI ({FileCount} files, {Size:N0} bytes)",
                fileMapping.Count, new FileInfo(cabPath).Length);
        }
        finally
        {
            // Cleanup temp directory
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    private static string EscSql(string value) => value.Replace("'", "''");

    private static string SanitizeIdentifier(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (var c in input)
        {
            if (char.IsLetterOrDigit(c) || c == '_')
                sb.Append(c);
            else
                sb.Append('_');
        }
        return sb.ToString();
    }
}
