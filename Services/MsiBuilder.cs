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

    // Standard MSI sequence numbers for InstallExecuteSequence.
    // FindRelatedProducts + RemoveExistingProducts supersede older builds of the
    // same product (same UpgradeCode) so ARP never accumulates copies — see
    // WriteInstallSequence and WriteUpgradeTable.
    private const int SeqLaunchConditions = 100;
    private const int SeqPreinstallScript = 3900;
    private const int SeqInstallFiles = 4000;
    private const int SeqPostinstallScript = 4100;
    private const int SeqInstallFinalize = 6600;

    /// <summary>
    /// Soft cap on the input bytes packed into a single embedded CAB stream.
    /// makecab.exe (and the underlying CAB format) tops out near 2 GB per
    /// cabinet; we hold ~500 MB of headroom both for compression overhead and
    /// to keep individual file extraction times sane. Payloads larger than
    /// this threshold are split across multiple cabinets via the standard MSI
    /// Media-row-per-cabinet pattern (the same model used by Office, Visual
    /// Studio, the Windows SDK, etc.).
    ///
    /// A single source file larger than the threshold still gets its own
    /// cabinet — we don't reject it. makecab will fail informatively if the
    /// resulting cabinet exceeds the format's hard limit, and the operator
    /// can split that file at the source.
    /// </summary>
    internal const long DefaultMaxBytesPerCabinet = 1_500_000_000L;

    /// <summary>
    /// Plan describing how a payload is sliced into one or more cabinets.
    /// Produced by <see cref="PlanCabinetSegments"/> and consumed by both
    /// <see cref="WritePayloadTables"/> (for Media/File rows) and
    /// <see cref="EmbedPayloadCabs"/> (for makecab invocation + stream
    /// embedding). Both consumers MUST agree on file→cabinet placement and
    /// sequence numbers, so they share this plan rather than independently
    /// re-deriving it.
    /// </summary>
    internal sealed record PayloadFile(
        string SourcePath,
        string RelativePath,
        string FileKey,
        string ComponentKey,
        Guid ComponentId,
        int Sequence,
        long Bytes);

    internal sealed record CabinetSegment(
        int DiskId,
        string CabinetName,
        IReadOnlyList<PayloadFile> Files);

    /// <summary>
    /// Group payload files into cabinet segments such that each segment's
    /// total uncompressed input bytes stays below <paramref name="maxBytesPerCabinet"/>.
    /// File order is preserved (matches caller's input order), and File.Sequence
    /// values are assigned 1..N contiguously across the entire payload.
    ///
    /// When the resulting plan contains exactly one segment, its CabinetName
    /// is "product.cab" — preserving the historical name for single-cabinet
    /// MSIs so external diagnostic tooling that recognizes that name keeps
    /// working. Multi-cabinet payloads use "product1.cab", "product2.cab", ...
    /// </summary>
    internal static IReadOnlyList<CabinetSegment> PlanCabinetSegments(
        string payloadDir,
        IReadOnlyList<string> payloadFiles,
        string identifier,
        long maxBytesPerCabinet = DefaultMaxBytesPerCabinet)
    {
        ArgumentNullException.ThrowIfNull(payloadDir);
        ArgumentNullException.ThrowIfNull(payloadFiles);
        ArgumentNullException.ThrowIfNull(identifier);
        if (maxBytesPerCabinet <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytesPerCabinet), "must be positive");

        var segments = new List<CabinetSegment>();
        var currentFiles = new List<PayloadFile>();
        long currentBytes = 0;
        int sequence = 1;
        int diskId = 1;

        void Flush()
        {
            if (currentFiles.Count == 0) return;
            segments.Add(new CabinetSegment(
                DiskId: diskId,
                CabinetName: $"product{diskId}.cab",
                Files: currentFiles));
            currentFiles = new List<PayloadFile>();
            currentBytes = 0;
            diskId++;
        }

        foreach (var filePath in payloadFiles)
        {
            var size = new FileInfo(filePath).Length;
            var rel = Path.GetRelativePath(payloadDir, filePath).Replace('\\', '/');
            var componentId = UpgradeCodeGenerator.GenerateComponentId(identifier, rel);

            // 72-char MSI identifier limit. The GUID-N form is 34 chars and
            // safely under 72 — no substring needed (substring would also throw
            // on a 34-char input).
            var fileKey = $"F_{SanitizeIdentifier(rel)}";
            if (fileKey.Length > 72) fileKey = $"F_{componentId:N}";
            var componentKey = $"C_{SanitizeIdentifier(rel)}";
            if (componentKey.Length > 72) componentKey = $"C_{componentId:N}";

            // Roll over to next cabinet if adding this file would overflow.
            // A single file larger than the threshold will still land in its
            // own (oversize) segment because the empty-segment check skips
            // the rollover when there's nothing to flush.
            if (currentFiles.Count > 0 && currentBytes + size > maxBytesPerCabinet)
                Flush();

            currentFiles.Add(new PayloadFile(
                SourcePath: filePath,
                RelativePath: rel,
                FileKey: fileKey,
                ComponentKey: componentKey,
                ComponentId: componentId,
                Sequence: sequence,
                Bytes: size));
            currentBytes += size;
            sequence++;
        }
        Flush();

        // Single-cabinet payloads keep the legacy "product.cab" name so the
        // common case stays byte-identical to pre-multicab cimipkg output.
        if (segments.Count == 1)
        {
            segments[0] = segments[0] with { CabinetName = "product.cab" };
        }

        return segments;
    }

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

        // Cabinet plan is computed inside the using block (it needs the MSI tables
        // open) but consumed after the database is committed (cabinets are
        // embedded as streams in a second pass). Hoisted here so it survives the
        // scope.
        IReadOnlyList<CabinetSegment> cabPlan = Array.Empty<CabinetSegment>();

        // Create the MSI database
        using (var db = new Database(msiPath, DatabaseOpenMode.Create))
        {
            _logger.LogDebug("Creating tables...");
            CreateTables(db);

            // Installer-type wraps a vendor MSI/EXE that registers its own ARP
            // entry — WriteProperties uses this to set ARPSYSTEMCOMPONENT=1 on
            // the wrapper so users don't see two rows for the same software.
            var isInstallerType = string.IsNullOrWhiteSpace(buildInfo.InstallLocation);

            _logger.LogDebug("Writing properties...");
            WriteProperties(db, productName, msiVersion, fullVersion, identifier,
                productCode, upgradeCode, buildInfo, buildInfoYaml, isInstallerType);

            _logger.LogDebug("Writing directory table...");
            WriteDirectoryTable(db, buildInfo.InstallLocation ?? string.Empty, isInstallerType, productName);

            // For scripts: installDir is where MSI puts files. For installer-type, this is
            // TempFolder\p_{guid} (resolved at install time). For copy-type, it's the actual path.
            var installDir = isInstallerType
                ? "[INSTALLDIR]"  // placeholder — actual path resolved at install time
                : buildInfo.InstallLocation!.TrimEnd('\\', '/');

            // Supersede any previously-installed build of this same product.
            // cimipkg MSIs are still stateless deployers — each one always runs
            // preinstall → copies payload → runs postinstall regardless of
            // what's on disk — but they must not accumulate: before this, every
            // build (random ProductCode, no removal) stacked a new ARP entry, so
            // a machine ended up with dozens of co-installed copies of the same
            // product sharing one keypath. The Upgrade row + FindRelatedProducts
            // + RemoveExistingProducts remove every other product with this
            // (deterministic) UpgradeCode so exactly one remains. The
            // IgnoreRemoveFailure attribute (see WriteUpgradeTable) makes removal
            // best-effort: a broken/unresolvable old package is skipped, never
            // aborting the new install — that abort was the field failure (#19)
            // that originally motivated dropping the table.
            WriteUpgradeTable(db, upgradeCode);

            // Plan the cabinet layout once; both WritePayloadTables (Media/File
            // rows) and EmbedPayloadCabs (makecab + stream embedding) consume
            // the same plan so file→cabinet placement and sequence numbers
            // stay in lockstep.
            if (payloadFiles.Length > 0)
            {
                cabPlan = PlanCabinetSegments(payloadDir, payloadFiles, identifier);
                _logger.LogDebug(
                    "Writing payload tables ({Files} files across {Cabs} cabinet(s))...",
                    payloadFiles.Length, cabPlan.Count);
                WritePayloadTables(db, cabPlan, msiVersion);
            }
            else
            {
                WriteEmptyFeature(db);
            }

            _logger.LogDebug("Writing install sequence...");
            WriteInstallSequence(db, hasScripts, hasPayloadFiles);

            _logger.LogDebug("Writing launch conditions...");
            WriteLaunchConditions(db);

            if (hasScripts)
            {
                _logger.LogDebug("Writing script custom actions...");
                WriteScriptCustomActions(db, scriptsDir, envVars, installDir, buildInfo);
            }

            _logger.LogDebug("Committing database...");
            db.Commit();
        }

        // Write Summary Information Stream after database is closed
        WriteSummaryInfo(msiPath, productName, msiVersion, buildInfo);

        // Embed each cabinet as a stream inside the MSI. For payloads larger
        // than ~1.5 GB this produces multiple cabinets (product1.cab,
        // product2.cab, ...) — see PlanCabinetSegments.
        if (cabPlan.Count > 0)
        {
            _logger.LogInformation(
                "Creating and embedding {Cabs} CAB archive(s) ({Files} files)...",
                cabPlan.Count, payloadFiles.Length);
            EmbedPayloadCabs(msiPath, cabPlan);
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

    internal static void CreateTables(Database db)
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

        // LaunchCondition / AppSearch / RegLocator — Windows Installer's
        // standard mechanism for aborting an install before any side effect
        // occurs. cimipkg writes one entry today (REBOOTPENDING) so a system
        // with a pending reboot fails fast with a clear message instead of
        // letting msiexec stumble into mid-install state. See WriteLaunchConditions.
        db.Execute("CREATE TABLE `LaunchCondition` (`Condition` CHAR(255) NOT NULL, `Description` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Condition`)");
        // AppSearch's PK is Property alone per the MSI standard schema — one
        // search result per property. A composite (Property, Signature_) key
        // would allow duplicate Property rows and deviate from what validation
        // tools (msival2, light) expect, making search results ambiguous if
        // duplicates ever crept in.
        db.Execute("CREATE TABLE `AppSearch` (`Property` CHAR(72) NOT NULL, `Signature_` CHAR(72) NOT NULL PRIMARY KEY `Property`)");
        db.Execute("CREATE TABLE `RegLocator` (`Signature_` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Type` SHORT PRIMARY KEY `Signature_`)");
        // Signature is the file-locator detail table. cimipkg writes no rows to
        // it (our only AppSearch entry is a Type-2 raw RegLocator value), but the
        // table MUST exist whenever AppSearch is sequenced. Some Windows Installer
        // engines — notably ones reporting the legacy 6.3/9600 profile under an
        // app-compat shim — eagerly run the file-locator probe
        // (SELECT FileName, MinVersion ... FROM `Signature` WHERE `Signature`=?)
        // while resolving AppSearch, regardless of whether any row references a
        // file signature. With the table absent that probe fails with error 2228
        // ("Unknown table 'Signature'"), AppSearch returns 3, and the whole
        // install aborts with 1603 before any payload or custom action runs.
        // An empty Signature table makes the probe a harmless no-match on every
        // engine while leaving the REBOOTPENDING RegLocator search intact.
        db.Execute("CREATE TABLE `Signature` (`Signature` CHAR(72) NOT NULL, `FileName` CHAR(255) NOT NULL LOCALIZABLE, `MinVersion` CHAR(20), `MaxVersion` CHAR(20), `MinSize` LONG, `MaxSize` LONG, `MinDate` LONG, `MaxDate` LONG, `Languages` CHAR(255) PRIMARY KEY `Signature`)");

        // Upgrade table. cimipkg uses it for one narrow purpose: detect and
        // remove ANY other product that shares this product's (deterministic)
        // UpgradeCode, so a build never piles a new ARP entry on top of the
        // previous ones. It is NOT a classic version-gated major upgrade — the
        // row matches every other version (see WriteUpgradeTable) so the most
        // recent install always wins and exactly one product remains. The
        // msidbUpgradeAttributesIgnoreRemoveFailure flag keeps a broken/
        // unresolvable old package from ever aborting the new install, which is
        // the field failure (#19) that previously motivated dropping this table.
        db.Execute("CREATE TABLE `Upgrade` (`UpgradeCode` CHAR(38) NOT NULL, `VersionMin` CHAR(20), `VersionMax` CHAR(20), `Language` CHAR(255), `Attributes` LONG NOT NULL, `Remove` CHAR(255), `ActionProperty` CHAR(72) NOT NULL PRIMARY KEY `UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`)");
    }

    /// <summary>
    /// Populates LaunchCondition + AppSearch + RegLocator with cimipkg's
    /// universal preflight checks. Today: REBOOTPENDING. Future: disk-space
    /// (needs a Type 19 error custom action since MSI's PrimaryVolumeSpaceAvailable
    /// only resolves after CostFinalize, too late for sequence 100).
    ///
    /// Set the build-time environment variable CIMIAN_PKG_DISABLE_LAUNCH_CONDITIONS=1
    /// to suppress all checks — kill switch for a misbehaving condition in the
    /// field. The tables themselves are still created so the schema is stable.
    /// </summary>
    private static void WriteLaunchConditions(Database db)
    {
        if (Environment.GetEnvironmentVariable("CIMIAN_PKG_DISABLE_LAUNCH_CONDITIONS") == "1")
        {
            return;
        }

        // REBOOTPENDING probe — HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
        //   Component Based Servicing\RebootPending. With Name=NULL the
        //   RegLocator search resolves to the *existence of the key itself*
        //   (per MSI docs) rather than any particular value, which is what we
        //   want for the CBS\RebootPending key — its presence alone signals a
        //   pending reboot. AppSearch copies the result into the REBOOTPENDING
        //   property; LaunchCondition fires if it ends up non-empty.
        db.Execute(
            "INSERT INTO `RegLocator` (`Signature_`, `Root`, `Key`, `Name`, `Type`) " +
            "VALUES ('Sig_CimianRebootPending', 2, " +
            "'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending', " +
            "NULL, 2)");
        db.Execute(
            "INSERT INTO `AppSearch` (`Property`, `Signature_`) " +
            "VALUES ('REBOOTPENDING', 'Sig_CimianRebootPending')");
        db.Execute(
            "INSERT INTO `LaunchCondition` (`Condition`, `Description`) " +
            "VALUES ('Installed OR NOT REBOOTPENDING', " +
            "'A pending Windows reboot must be completed before this Cimian package can be installed. " +
            "Please reboot the computer and run the installer again.')");
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
        string buildInfoYaml,
        bool isInstallerType)
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

        // Standard MSI properties.
        // UpgradeCode drives same-product supersession via the Upgrade table
        // (FindRelatedProducts / RemoveExistingProducts) and is also read by
        // downstream tooling (managedsoftwareupdate, cimistatus, ReportMate) via
        // MsiPropertyReader for status correlation.
        SetProperty("ProductName", productName);
        SetProperty("ProductVersion", msiVersion);
        SetProperty("ProductCode", $"{{{productCode}}}");
        SetProperty("UpgradeCode", $"{{{upgradeCode}}}");
        // SecureCustomProperties (which must list PREVIOUSVERSIONSINSTALLED for the
        // upgrade machinery) is written once, after the user msi_properties loop
        // below, so a package-supplied value is unioned rather than colliding on
        // the Property table primary key.
        SetProperty("Manufacturer", buildInfo.Product.Developer ?? "Unknown");
        SetProperty("ProductLanguage", "1033");
        SetProperty("ALLUSERS", "1");
        SetProperty("ARPNOREPAIR", "1");
        SetProperty("ARPNOMODIFY", "1");
        // Installer-type packages wrap a vendor installer (MSI/EXE) that registers
        // its own Add/Remove Programs entry. Without ARPSYSTEMCOMPONENT=1, users
        // see two ARP rows for the same software — the cimipkg wrapper and the
        // vendor's entry. SystemComponent=1 keeps the wrapper installed and
        // visible to MSI tooling (managedsoftwareupdate / managedreportsrunner
        // read it via MsiPropertyReader from the registry, not the ARP UI) while
        // hiding it from Programs and Features. Originally added in PR #22; the
        // REBOOTPENDING work in PR #23 dropped it by accident — restored here.
        if (isInstallerType)
            SetProperty("ARPSYSTEMCOMPONENT", "1");
        SetProperty("MSIFASTINSTALL", "7");
        SetProperty("MsiLogging", "voicewarmup");

        // Suppress reboots
        SetProperty("REBOOT", "ReallySuppress");
        SetProperty("MSIRESTARTMANAGERCONTROL", "Disable");

        // Force aggressive reinstall on any repair/reinstall operation:
        //   a - reinstall all files regardless of version/checksum/date
        //   m - rewrite all required HKLM registry entries
        //   u - rewrite all required HKCU registry entries
        //   s - reinstall all shortcuts and re-cache icons
        // Fresh installs use the synthetic File.Version set in WritePayloadTables
        // (see the "Extract PE FileVersion..." block) to force rule-1 overwrites,
        // so between the two, cimipkg MSIs always replace on-disk payload files.
        // The MSI is the source of truth.
        SetProperty("REINSTALLMODE", "amus");

        // ARP (Add/Remove Programs) properties
        if (!string.IsNullOrEmpty(buildInfo.Product.Description))
            SetProperty("ARPCOMMENTS", buildInfo.Product.Description);
        if (!string.IsNullOrEmpty(buildInfo.Product.Url))
            SetProperty("ARPURLINFOABOUT", buildInfo.Product.Url);

        // Cimian-specific properties (all use CIMIAN_PKG_ prefix)
        SetProperty("CIMIAN_PKG_IDENTIFIER", identifier);
        SetProperty("CIMIAN_PKG_FULL_VERSION", fullVersion);
        // CIMIAN_PKG_BUILD_INFO is the signal that downstream readers
        // (MsiPropertyReader, MsiMetadata.IsCimianPackage) use to recognize a
        // cimipkg-built MSI. It MUST stay present. Encode the YAML as base64 so
        // the value is single-line: a multi-line Property value confuses MSI's
        // verbose property dump (subsequent properties appear concatenated) and
        // — far worse — caused PREVIOUSVERSIONSINSTALLED to resolve to the YAML
        // blob at runtime, breaking every condition that referenced it.
        // MsiPropertyReader.ReadMetadata transparently base64-decodes when it
        // sees a value matching this shape; older readers will see an opaque
        // string but IsCimianPackage stays true (non-empty value).
        if (!string.IsNullOrEmpty(buildInfoYaml))
        {
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(buildInfoYaml));
            SetProperty("CIMIAN_PKG_BUILD_INFO", encoded);
        }

        // User-supplied msi_properties from build-info.yaml are written verbatim,
        // with one exception: SecureCustomProperties must always include
        // PREVIOUSVERSIONSINSTALLED — it is set by FindRelatedProducts and consumed
        // by RemoveExistingProducts, and declaring it secure lets the value cross
        // the UI→execute boundary intact and pass ICE validation. If a package also
        // supplies SecureCustomProperties we union the two semicolon-delimited lists
        // and emit a single Property row, rather than inserting the key twice and
        // colliding on the Property table primary key.
        var secureProps = new List<string> { "PREVIOUSVERSIONSINSTALLED" };
        if (buildInfo.MsiProperties != null)
        {
            foreach (var (key, value) in buildInfo.MsiProperties)
            {
                if (string.Equals(key, "SecureCustomProperties", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var p in value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        if (!secureProps.Contains(p, StringComparer.OrdinalIgnoreCase))
                            secureProps.Add(p);
                    }
                    continue;
                }
                SetProperty(key, value);
            }
        }
        SetProperty("SecureCustomProperties", string.Join(";", secureProps));
    }

    /// <summary>
    /// Writes the single Upgrade row that drives same-product supersession.
    /// FindRelatedProducts populates PREVIOUSVERSIONSINSTALLED from any other
    /// installed product carrying this UpgradeCode; RemoveExistingProducts then
    /// uninstalls them (early in the sequence — see WriteInstallSequence) so only
    /// the build now installing remains.
    ///
    /// VersionMin='0.0.0' (exclusive) with an empty VersionMax matches every real
    /// version, so this is deliberately not a version-gated upgrade: the most
    /// recent install always wins regardless of the timestamp version it carries
    /// (two builds can even share an MSI version when stamped in the same minute).
    ///
    /// Attributes = 4 (msidbUpgradeAttributesIgnoreRemoveFailure) | 256
    /// (msidbUpgradeAttributesLanguagesExclusive, i.e. all languages). The
    /// IgnoreRemoveFailure bit is load-bearing: if an old product's cached package
    /// is missing or corrupt, its removal is skipped and the new install still
    /// completes with exit 0 — never the silent /qn source-prompt abort that #19
    /// removed this machinery to avoid.
    /// </summary>
    internal static void WriteUpgradeTable(Database db, Guid upgradeCode)
    {
        const int ignoreRemoveFailure = 4;
        const int languagesExclusive = 256;
        var attributes = ignoreRemoveFailure | languagesExclusive;
        db.Execute(
            "INSERT INTO `Upgrade` (`UpgradeCode`, `VersionMin`, `VersionMax`, `Language`, `Attributes`, `Remove`, `ActionProperty`) " +
            $"VALUES ('{{{upgradeCode}}}', '0.0.0', '', '', {attributes}, '', 'PREVIOUSVERSIONSINSTALLED')");
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

    private void WritePayloadTables(
        Database db,
        IReadOnlyList<CabinetSegment> segments,
        string msiVersion)
    {
        // One Media row per cabinet. LastSequence is the highest File.Sequence
        // value contained in that cabinet — MSI uses these ranges to know which
        // cabinet to crack open when extracting a given file. The '#' prefix on
        // Cabinet marks it as an embedded stream (vs an external file sibling).
        foreach (var seg in segments)
        {
            var lastSeq = seg.Files[^1].Sequence;
            db.Execute($"INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, `VolumeLabel`, `Source`) VALUES ({seg.DiskId}, {lastSeq}, '', '#{EscSql(seg.CabinetName)}', '', '')");
        }

        // Single feature
        db.Execute(
            "INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, `Level`, `Directory_`, `Attributes`) VALUES ('DefaultFeature', '', 'Complete', 'Full installation', 1, 1, 'INSTALLDIR', 0)");

        // Cache of created Directory rows, keyed by cumulative sub-path beneath INSTALLDIR.
        // Each segment becomes its own Directory row (MSI's DefaultDir column cannot
        // encode a multi-segment path — '|' there is the short|long separator, not a
        // path delimiter). Without proper nesting, every file with a path like
        // "runtimes/win/lib/net9.0/Modules/X/Y.psd1" collapses into INSTALLDIR, which
        // collides with other files of the same basename under different parents.
        var dirCache = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [string.Empty] = "INSTALLDIR",
        };

        foreach (var seg in segments)
        foreach (var pf in seg.Files)
        {
            var relativePath = pf.RelativePath;
            var filePath = pf.SourcePath;
            var fileName = Path.GetFileName(filePath);
            var fileSize = pf.Bytes;
            var fileKey = pf.FileKey;
            var componentKey = pf.ComponentKey;
            var componentId = pf.ComponentId;
            var sequence = pf.Sequence;

            // Walk the relative path's parent segments, creating nested Directory rows on
            // demand. Returns the Directory identifier to use as Component.Directory_.
            var directoryRef = EnsureDirectoryChain(db, dirCache, Path.GetDirectoryName(relativePath));

            // MSI FileName format: "ShortName|LongName"
            var shortName = GenerateShortName(fileName, sequence);
            var msiFileName = $"{shortName}|{fileName}";

            // Component: Attributes=256 means 64-bit component
            var cid = EscSql($"{{{componentId}}}");
            db.Execute($"INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, `Condition`, `KeyPath`) VALUES ('{EscSql(componentKey)}', '{cid}', '{EscSql(directoryRef)}', 256, '', '{EscSql(fileKey)}')");

            // Extract PE FileVersion so Windows Installer's file versioning rules work.
            // For unversioned files (.ps1, .json, .txt, etc.) we fall back to the package
            // version so MSI still treats them as "versioned" and applies rule 1 of the
            // file install rules (newer version wins). Without a File.Version, MSI uses
            // the "unversioned vs user-modified" rule which refuses to overwrite files
            // it considers to have been edited on disk - exactly the behavior that caused
            // v2026.04.10.1431 RenderingManager to silently ship stale scripts to 142
            // endpoints because leftover .ps1 files from the pre-MSI packages blocked
            // the MSI from writing the new content.
            //
            // The synthetic version is safe even for files that are genuinely unversioned
            // on disk: MSI only uses File.Version for comparison, it does not try to read
            // a version resource from non-PE files. So the only observable effect is that
            // the cimipkg MSI becomes an authoritative source of truth for its payload.
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
            catch (Exception ex) when (
                ex is System.IO.IOException ||
                ex is System.IO.FileNotFoundException ||
                ex is UnauthorizedAccessException ||
                ex is ArgumentException ||
                ex is NotSupportedException)
            {
                // Narrow set of expected I/O / access issues when reading PE metadata.
                // Log + fall through to the synthetic-version fallback below so operators
                // get a breadcrumb but the MSI still guarantees overwrite semantics.
                _logger.LogWarning(
                    "Failed to read PE file version for '{FilePath}': {Error}. Falling back to package version for MSI File.Version.",
                    filePath, ex.Message);
            }

            if (string.IsNullOrEmpty(fileVersion))
            {
                // Fallback: stamp unversioned files with the package version so MSI
                // treats every cimipkg build as newer than whatever is on disk. This
                // is what makes cimipkg MSIs the source of truth for their payloads.
                //
                // MsiVersionConverter returns a 3-part MSI version (major.minor.build),
                // but the MSI File.Version column is validated against the 4-part
                // major.minor.build.revision shape. A 3-part value silently falls back
                // to "unversioned" and the rule we are trying to avoid reasserts
                // itself, so pad to 4 parts before writing.
                fileVersion = NormalizeToFourPartVersion(msiVersion);
            }

            // File
            db.Execute($"INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Version`, `Language`, `Attributes`, `Sequence`) VALUES ('{EscSql(fileKey)}', '{EscSql(componentKey)}', '{EscSql(msiFileName)}', {fileSize}, '{EscSql(fileVersion)}', '', 0, {sequence})");

            // FeatureComponents
            db.Execute($"INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES ('DefaultFeature', '{EscSql(componentKey)}')");

            _logger.LogDebug("Added file: {RelativePath} ({Size} bytes, cabinet {Cabinet})",
                relativePath, fileSize, seg.CabinetName);
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

    internal static void WriteInstallSequence(Database db, bool hasScripts, bool hasPayload)
    {
        void AddAction(string action, string? condition, int sequence)
        {
            db.Execute($"INSERT INTO `InstallExecuteSequence` (`Action`, `Condition`, `Sequence`) VALUES ('{EscSql(action)}', '{EscSql(condition ?? "")}', {sequence})");
        }

        // Standard install sequence.
        //
        // AppSearch MUST run before LaunchConditions so the REBOOTPENDING
        // property is populated before the launch condition evaluates it.
        // The MSI standard puts AppSearch at sequence 50 for exactly this
        // reason — running it at 400 (after LaunchConditions at 100) means
        // the condition sees an empty property and never fires.
        AddAction("AppSearch", null, 50);
        AddAction("LaunchConditions", null, 100);
        // FindRelatedProducts populates PREVIOUSVERSIONSINSTALLED from the Upgrade
        // table so RemoveExistingProducts (below) knows which older builds of this
        // same product to uninstall. Standard placement is early, before costing.
        AddAction("FindRelatedProducts", null, 200);
        // NOTE: cimipkg deliberately does NOT force REINSTALL=ALL on re-runs.
        // An earlier attempt set REINSTALL=ALL here to make a same-ProductCode
        // re-run re-lay payload — but REINSTALL is Windows Installer's *repair*
        // path, and on any machine with SecureRepair active (default on modern
        // Windows) the repair is validated against the original install source.
        // BootstrapMate downloads each MSI to an ephemeral cache and clears it
        // between runs, so that source is gone and SecureRepair aborts the whole
        // install with 1603 (or 1625 outside an elevated context). That is exactly
        // the "MSI maintenance/repair machinery" this tool is built to avoid.
        // What replaces it, without the repair engine:
        //   * Scripts run on EVERY install. CimianPreinstall / CimianPostinstall are
        //     custom actions gated only on install-vs-uninstall (NOT REMOVE="ALL"),
        //     so the package's own logic executes on every msiexec /i, fresh or repeat.
        //   * Payload is laid by the standard component-based InstallFiles action.
        //     Each File carries a synthetic File.Version (the package version, see
        //     WritePayloadTables) so a NEW build always overwrites whatever is on disk,
        //     and supersede (RemoveExistingProducts) makes every new version a fresh
        //     install. A byte-identical re-run of the SAME version is a maintenance
        //     no-op for the files — they are already present — which is fine: nothing
        //     changed, and we never invoke repair to force a redundant re-copy.
        AddAction("CostInitialize", null, 800);
        AddAction("FileCost", null, 900);
        AddAction("CostFinalize", null, 1000);
        AddAction("InstallValidate", null, 1400);
        AddAction("InstallInitialize", null, 1500);
        // RemoveExistingProducts runs early (right after InstallInitialize, before
        // the new payload is laid down) so superseded builds are gone before
        // ProcessComponents/InstallFiles, minimizing the window where two copies of
        // the same product overlap. IgnoreRemoveFailure on the Upgrade row means a
        // broken old package is skipped rather than aborting this install.
        AddAction("RemoveExistingProducts", null, 1525);
        AddAction("ProcessComponents", null, 1600);
        AddAction("UnpublishFeatures", null, 1800);

        if (hasScripts)
        {
            // Preinstall fires on every install operation, skipped only on uninstall.
            // The previous gating on PREVIOUSVERSIONSINSTALLED OR REINSTALL was a
            // by-product of the upgrade machinery we no longer use; with the Upgrade
            // table gone, the property is never populated and the script would
            // never have run on the new build anyway. The contract is "preinstall
            // always runs first when the package is being installed."
            //
            // Sequence 1398 places this BEFORE InstallValidate (1400). Why it must
            // run before InstallValidate, not just before InstallInitialize: when
            // the package being installed contains an .exe that's currently held
            // open by a running service (e.g. cimiwatcher.exe), InstallValidate
            // detects the lock and tries to display a Files-In-Use dialog. With
            // MSIRESTARTMANAGERCONTROL=Disable and a service that has no window,
            // there's no dialog to show and no window to find — InstallValidate
            // sits in a ~110-second timeout before falling through. Running the
            // preinstall script (which stops the service) before sequence 1400
            // means InstallValidate sees nothing locked and proceeds immediately.
            AddAction("CimianPreinstall", "NOT (REMOVE=\"ALL\")", 1398);
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
            // Postinstall and uninstall are deferred + no-impersonate (run as LocalSystem),
            // so they MUST be sequenced between InstallInitialize (1500) and InstallFinalize
            // (6600) — a deferred action scheduled after InstallFinalize is never written
            // into the execute-sequence script and silently never runs. They sit just before
            // InstallFinalize: all payload files are on disk (InstallFiles 4000) and the
            // product is registered (RegisterProduct 6100), and running before the commit
            // means a failing install-phase script rolls the whole install back cleanly
            // rather than leaving a committed-but-misconfigured product.
            //
            // Each deferred action is preceded by its immediate Type 51 set-property
            // companion (Set<Action>Data) that marshals INSTALLDIR/REMOVE/ProductVersion/
            // ProductName into CustomActionData — the only property a deferred CA can read.
            //
            // Postinstall fires on every install operation, skipped only on uninstall.
            AddAction("SetCimianPostinstallData", "NOT (REMOVE=\"ALL\")", 6450);
            AddAction("CimianPostinstall", "NOT (REMOVE=\"ALL\")", 6500);
            // Uninstall fires only on a genuine standalone uninstall. The
            // UPGRADINGPRODUCTCODE guard skips this CA when the product is being
            // removed as the superseded side of an install (RemoveExistingProducts
            // sets UPGRADINGPRODUCTCODE on the old product), so replacing an old
            // build does not run its uninstall script — only an explicit removal
            // does.
            AddAction("SetCimianUninstallData", "REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE", 6460);
            AddAction("CimianUninstall", "REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE", 6510);
        }
    }

    private void WriteScriptCustomActions(
        Database db,
        string scriptsDir,
        Dictionary<string, string> envVars,
        string installDir,
        BuildInfo buildInfo)
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

        // Preinstall: immediate, before InstallValidate — stops services/processes that
        // hold payload files open so InstallValidate doesn't stall on a Files-In-Use check.
        // It MUST be immediate (a deferred CA cannot run before InstallInitialize), which
        // means it runs in the launching context — fine for the elevated fleet path
        // (Cimian/SYSTEM, BootstrapMate). See WriteInstallSequence for the timing rationale.
        var preScript = preinstallScripts.Length > 0
            ? SignScriptContent(variableHeader + CombineScripts(preinstallScripts, envVars), buildInfo)
            : "# No preinstall scripts";
        WriteImmediateScriptAction(db, "CimianPreinstall", preScript);

        // Postinstall: deferred + no-impersonate, scheduled just before InstallFinalize so
        // it runs as LocalSystem on every launch path (double-click, msiexec, Cimian). An
        // immediate postinstall ran in the launching user's token, so a non-elevated
        // attended install could not write HKLM and failed with 1720.
        var postScript = postinstallScripts.Length > 0
            ? SignScriptContent(variableHeader + CombineScripts(postinstallScripts, envVars), buildInfo)
            : "# No postinstall scripts";
        WriteDeferredScriptAction(db, "CimianPostinstall", postScript);

        // Uninstall: deferred + no-impersonate, during removal.
        var uninstallScript = uninstallScripts.Length > 0
            ? SignScriptContent(variableHeader + CombineScripts(uninstallScripts, envVars), buildInfo)
            : "# No uninstall scripts";
        WriteDeferredScriptAction(db, "CimianUninstall", uninstallScript);
    }

    /// <summary>
    /// Write a Type 38 inline VBScript custom action that runs a PowerShell script
    /// of arbitrary size. The VBS ships the PS1 content as a chunked base64 string,
    /// decodes it at install time via MSXML + ADODB.Stream, writes it to a temp
    /// .ps1 file, and invokes <c>powershell.exe -File</c> on it.
    ///
    /// Why not the obvious <c>-EncodedCommand</c> approach:
    /// the previous implementation inlined the base64 into a single <c>ws.Run</c>
    /// line. For any non-trivial postinstall script (~15 KB of PS1 is common) that
    /// line grew past three hard limits simultaneously:
    ///   * VBScript parser chokes at ~1022 chars per source line
    ///   * <c>CreateProcess</c> command line limit is 32,767 chars
    ///   * Legacy cmd.exe limit is 8,191 chars
    /// which produced <c>Info 1720. ... script error -2147024690, Line 5, Column 1</c>
    /// at install time and caused the whole custom action to silently no-op.
    /// RenderingManager v2026.04.10.1431 hit exactly this, which is why DiagnoseSystem
    /// and MonitorAlerts scheduled tasks never got registered on 142 endpoints.
    ///
    /// The temp-file approach side-steps all three limits: the base64 lives in a
    /// normal VBS variable built from many short <c>&amp;</c> concatenations, then
    /// only the short temp-file path is passed to <c>powershell.exe</c>.
    /// </summary>
    private static void WriteImmediateScriptAction(Database db, string actionName, string scriptContent)
    {
        var vbsStr = BuildScriptActionVbs(actionName, scriptContent);
        // Type 38 = inline VBScript (Target column), immediate. Used only for
        // CimianPreinstall now (postinstall/uninstall are deferred — see
        // WriteDeferredScriptAction). Deliberately NOT +64 (msidbCustomActionTypeContinue):
        // a failing install-phase preinstall must fail the MSI so the managing client
        // records a failed install instead of a phantom success that installchecks then
        // refute forever (the WinAdminsAccount install-loop incident, June 2026). The VBS
        // itself only raises for cimianPhase = "install".
        db.Execute($"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`, `ExtendedType`) VALUES ('{EscSql(actionName)}', 38, '', '{EscSql(vbsStr)}', 0)");
    }

    /// <summary>
    /// Write a deferred, no-impersonate Type 3110 VBScript custom action plus the Type 51
    /// set-property companion that feeds it CustomActionData.
    ///
    /// Why deferred + no-impersonate instead of the immediate Type 38: an immediate custom
    /// action runs in the security context of the process that launched the install. When a
    /// cimipkg MSI is installed by an elevated launcher (Cimian/managedsoftwareupdate as
    /// SYSTEM, an elevated BootstrapMate, or msiexec from an elevated prompt) that context is
    /// already SYSTEM/admin, so an immediate postinstall could write HKLM and everything
    /// worked. But a plain double-click in Explorer by a non-elevated user runs the immediate
    /// custom action in the *user's* unelevated token even though the install itself elevates
    /// — so a postinstall that writes HKLM (e.g. CimianAuth's credential setup) failed, and
    /// once cimipkg started failing the install on a non-zero script exit that surfaced as
    /// MSI error 1720 ("a script required for this install to complete could not be run"),
    /// orphaning attended-provisioned devices. Deferred (msidbCustomActionTypeInScript, 1024)
    /// + no-impersonate (msidbCustomActionTypeNoImpersonate, 2048) runs the script as
    /// LocalSystem inside the install's elevated execute-sequence script, so it succeeds the
    /// same way no matter how the MSI was launched.
    ///
    /// Type 3110 = 38 (the same inline-VBScript-in-Target base type as the immediate action)
    /// + 1024 + 2048. Deliberately NOT +64 (msidbCustomActionTypeContinue): a failing
    /// install-phase script must fail — and now cleanly roll back — the MSI, because the
    /// deferred action runs before InstallFinalize commits.
    /// </summary>
    private static void WriteDeferredScriptAction(Database db, string actionName, string scriptContent)
    {
        var vbsStr = BuildScriptActionVbs(actionName, scriptContent, deferred: true);
        db.Execute($"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`, `ExtendedType`) VALUES ('{EscSql(actionName)}', 3110, '', '{EscSql(vbsStr)}', 0)");

        // Type 51 (set-property) companion: a deferred CA can only read the single
        // CustomActionData property, whose name must match the deferred action. Stage the
        // four values the VBS needs (INSTALLDIR for installer-type payload root, REMOVE for
        // the install/uninstall phase, ProductVersion, ProductName for the sidecar log name)
        // pipe-delimited. The Source column is the property to set (== the deferred action
        // name); the Target column is formatted by MSI at run time so [INSTALLDIR] etc.
        // expand to their resolved values. This must be sequenced before the deferred action
        // (see WriteInstallSequence) so the property is set when MSI snapshots CustomActionData.
        var setActionName = "Set" + actionName + "Data";
        const string data = "[INSTALLDIR]|[REMOVE]|[ProductVersion]|[ProductName]";
        db.Execute($"INSERT INTO `CustomAction` (`Action`, `Type`, `Source`, `Target`, `ExtendedType`) VALUES ('{EscSql(setActionName)}', 51, '{EscSql(actionName)}', '{EscSql(data)}', 0)");
    }

    /// <summary>
    /// Build the VBScript body for a Cimian script custom action. Public so the test
    /// project can assert on the generated VBS without having to create an MSI database.
    /// </summary>
    public static string BuildScriptActionVbs(string actionName, string scriptContent, bool deferred = false)
    {
        // <paramref name="deferred"/> switches how the four MSI values the script needs
        // (INSTALLDIR, REMOVE, ProductVersion, ProductName) are obtained. An immediate CA
        // reads them straight off the running session via Session.Property(); a deferred CA
        // runs in the elevated execute-sequence script where Session.Property() returns
        // empty for everything except CustomActionData, so a companion Type 51 set-property
        // CA marshals them pipe-delimited into CustomActionData and the VBS Splits them out.
        // Deferred + no-impersonate is what lets the script run as LocalSystem regardless of
        // how the MSI was launched (see WriteDeferredScriptAction).
        //
        // actionName is interpolated directly into both VBS string literals and the
        // staged temp-file path, so reject anything that could break either surface.
        // cimipkg only ever passes the fixed values CimianPreinstall /
        // CimianPostinstall / CimianUninstall, but the method is public for tests
        // and we want a loud failure rather than a corrupted MSI if a caller
        // accidentally passes user-controlled data.
        if (string.IsNullOrEmpty(actionName))
        {
            throw new ArgumentException("actionName must not be null or empty", nameof(actionName));
        }
        foreach (var c in actionName)
        {
            if (!char.IsLetterOrDigit(c) && c != '_' && c != '-')
            {
                throw new ArgumentException(
                    $"actionName must only contain letters, digits, '_' or '-'; got '{actionName}'",
                    nameof(actionName));
            }
        }

        // Encode as UTF-8 **with BOM** so PowerShell 5.1 reads the file reliably
        // when invoked via `powershell.exe -File`. Without a BOM, PS 5.1 falls back
        // to the system ANSI code page and mis-parses Unicode content — and because
        // we write the bytes via ADODB.Stream in binary mode, there is no automatic
        // BOM emission. The 3-byte 0xEF 0xBB 0xBF preamble is prepended explicitly
        // so every staged script opens as UTF-8 regardless of the host locale.
        //
        // UTF-8 also nearly halves the base64 transport size compared to UTF-16LE
        // for ASCII-dominant PowerShell source, which keeps the MSI
        // CustomAction.Target column well under its LONGCHAR budget for even very
        // large postinstall scripts.
        var bom = Encoding.UTF8.GetPreamble(); // 0xEF 0xBB 0xBF
        var body = Encoding.UTF8.GetBytes(scriptContent);
        var bytes = new byte[bom.Length + body.Length];
        Buffer.BlockCopy(bom, 0, bytes, 0, bom.Length);
        Buffer.BlockCopy(body, 0, bytes, bom.Length, body.Length);
        var base64 = Convert.ToBase64String(bytes);

        // 800-char chunks keep each VBS source line comfortably under the parser's
        // ~1022 char hard limit once wrapped in `b64 = b64 & "..."`.
        const int chunkSize = 800;

        var vbs = new StringBuilder(base64.Length + 4096);
        vbs.Append("On Error Resume Next\r\n");
        vbs.Append("Dim ws, fso, xml, node, stream, tmpFile, b64, rc, psExe, sysRoot, progFiles\r\n");
        vbs.Append("Dim cimianPhase, cimianRemove, cimianInstallDir, cimianVersion, cimianProdName\r\n");
        vbs.Append("Dim q, cmdLine, logFile, logDir, logStream, logLine, lineCount, prodName, ch\r\n");
        vbs.Append("Dim cimianData, cimianParts\r\n");
        vbs.Append("Set ws = CreateObject(\"WScript.Shell\")\r\n");
        vbs.Append("Set fso = CreateObject(\"Scripting.FileSystemObject\")\r\n");
        // Obtain the four values the script needs. A deferred CA cannot read arbitrary
        // properties (Session.Property returns empty except for CustomActionData), so its
        // companion Type 51 set-property CA stages them pipe-delimited into CustomActionData
        // as INSTALLDIR|REMOVE|ProductVersion|ProductName — none of which can contain a '|'
        // (Windows paths, the package version, and the sanitized product name never do, and
        // REMOVE is only ever "ALL" or empty), so a positional Split round-trips safely.
        if (deferred)
        {
            vbs.Append("cimianData = Session.Property(\"CustomActionData\")\r\n");
            vbs.Append("cimianInstallDir = \"\" : cimianRemove = \"\" : cimianVersion = \"\" : cimianProdName = \"\"\r\n");
            vbs.Append("cimianParts = Split(cimianData, \"|\")\r\n");
            vbs.Append("If UBound(cimianParts) >= 0 Then cimianInstallDir = cimianParts(0)\r\n");
            vbs.Append("If UBound(cimianParts) >= 1 Then cimianRemove = cimianParts(1)\r\n");
            vbs.Append("If UBound(cimianParts) >= 2 Then cimianVersion = cimianParts(2)\r\n");
            vbs.Append("If UBound(cimianParts) >= 3 Then cimianProdName = cimianParts(3)\r\n");
        }
        else
        {
            vbs.Append("cimianInstallDir = Session.Property(\"INSTALLDIR\")\r\n");
            vbs.Append("cimianRemove = Session.Property(\"REMOVE\")\r\n");
            vbs.Append("cimianVersion = Session.Property(\"ProductVersion\")\r\n");
            vbs.Append("cimianProdName = Session.Property(\"ProductName\")\r\n");
        }
        // Surface the MSI INSTALLDIR to PowerShell exactly like sbin-installer
        // surfaces the extraction dir - preinstall/postinstall scripts can read
        // $env:CIMIAN_INSTALLDIR (or the injected $payloadRoot variable).
        vbs.Append("ws.Environment(\"Process\")(\"CIMIAN_INSTALLDIR\") = cimianInstallDir\r\n");
        // Phase is just install vs uninstall — cimipkg MSIs do not participate
        // in major upgrades, so PREVIOUSVERSIONSINSTALLED / UPGRADINGPRODUCTCODE
        // are never populated and the prior "upgrade"/"fresh" branches never
        // fired meaningfully.
        vbs.Append("If cimianRemove = \"ALL\" Then\r\n");
        vbs.Append("  cimianPhase = \"uninstall\"\r\n");
        vbs.Append("Else\r\n");
        vbs.Append("  cimianPhase = \"install\"\r\n");
        vbs.Append("End If\r\n");
        vbs.Append("ws.Environment(\"Process\")(\"CIMIAN_PHASE\") = cimianPhase\r\n");
        vbs.Append("ws.Environment(\"Process\")(\"CIMIAN_VERSION\") = cimianVersion\r\n");
        vbs.Append($"Session.Log \"{actionName}: phase=\" & cimianPhase & \" version=\" & cimianVersion\r\n");
        //
        // Resolve the PowerShell runtime at install time so the same cimipkg MSI
        // works on endpoints with or without PowerShell 7 installed:
        //   1. Default to powershell.exe 5.1 from %SystemRoot% (guaranteed to be
        //      present on every supported Windows image, including Server Core).
        //   2. Upgrade to pwsh.exe 7 if it is installed in the standard path
        //      (`C:\Program Files\PowerShell\7\pwsh.exe`). We look in the stable
        //      directory first, then fall through to `7-preview` as a courtesy
        //      for dev machines; both are official PowerShell install layouts.
        // Scripts should stay 5.1-safe so they run under either runtime, but
        // anything added via `#Requires -Version 7` will now execute under pwsh
        // instead of silently failing under 5.1 when pwsh is installed.
        //
        // Probing via `fso.FileExists` is cheap (no disk IO beyond a directory
        // lookup) and keeps the resolver fully local to the custom action — no
        // PATH dependency, no registry reads. We expand %SystemRoot% and
        // %ProgramW6432% at install time so the MSI works on any drive letter.
        vbs.Append("sysRoot = ws.ExpandEnvironmentStrings(\"%SystemRoot%\")\r\n");
        vbs.Append("progFiles = ws.ExpandEnvironmentStrings(\"%ProgramW6432%\")\r\n");
        vbs.Append("psExe = sysRoot & \"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"\r\n");
        vbs.Append("If fso.FileExists(progFiles & \"\\PowerShell\\7\\pwsh.exe\") Then\r\n");
        vbs.Append("  psExe = progFiles & \"\\PowerShell\\7\\pwsh.exe\"\r\n");
        vbs.Append("ElseIf fso.FileExists(progFiles & \"\\PowerShell\\7-preview\\pwsh.exe\") Then\r\n");
        vbs.Append("  psExe = progFiles & \"\\PowerShell\\7-preview\\pwsh.exe\"\r\n");
        vbs.Append("End If\r\n");
        vbs.Append($"Session.Log \"{actionName}: using \" & psExe\r\n");
        vbs.Append("b64 = \"\"\r\n");
        for (int i = 0; i < base64.Length; i += chunkSize)
        {
            var len = Math.Min(chunkSize, base64.Length - i);
            vbs.Append("b64 = b64 & \"");
            vbs.Append(base64, i, len);
            vbs.Append("\"\r\n");
        }
        // MSXML base64 decode -> binary stream -> temp file.
        // Msxml2.DOMDocument.6.0 and ADODB.Stream are both part of the Windows
        // base image since XP, so they are available inside the msiexec sandbox.
        // Clear Err before staging so the check at the end only catches staging
        // failures (decode/write), not earlier non-fatal errors from e.g. env
        // variable assignment or fso.FileExists probes.
        // Seed rc before staging so a staging failure (script never ran) is
        // indistinguishable from a launch failure at the final exit-code check.
        vbs.Append("rc = -1\r\n");
        vbs.Append("Err.Clear\r\n");
        vbs.Append("Set xml = CreateObject(\"Msxml2.DOMDocument.6.0\")\r\n");
        vbs.Append("Set node = xml.CreateElement(\"b\")\r\n");
        vbs.Append("node.DataType = \"bin.base64\"\r\n");
        vbs.Append("node.Text = b64\r\n");
        vbs.Append("Set stream = CreateObject(\"ADODB.Stream\")\r\n");
        vbs.Append("stream.Type = 1\r\n"); // adTypeBinary
        vbs.Append("stream.Open\r\n");
        vbs.Append("stream.Write node.NodeTypedValue\r\n");
        // Millisecond-unique temp path under SYSTEM's %TEMP% (C:\Windows\Temp when elevated).
        // Using Timer() avoids needing a GUID generator in VBS.
        vbs.Append($"tmpFile = ws.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\cimian-{actionName}-\" & CLng(Timer * 1000) & \".ps1\"\r\n");
        vbs.Append("stream.SaveToFile tmpFile, 2\r\n"); // adSaveCreateOverWrite
        vbs.Append("stream.Close\r\n");
        vbs.Append("If Err.Number <> 0 Then\r\n");
        vbs.Append($"  Session.Log \"{actionName}: failed to stage temp script: \" & Err.Description\r\n");
        vbs.Append("Else\r\n");
        vbs.Append($"  Session.Log \"{actionName}: running \" & tmpFile\r\n");
        // ws.Run "powershell.exe" -NoProfile ... -File "<tmpFile>", 0, True
        // VBS quoting: "" produces a literal " inside a string literal, so """X""" = "X"
        //
        // Under `On Error Resume Next` a ws.Run() failure to even START the process
        // (bad exe path, quoting bug, access denied) does not surface via `rc`;
        // instead `Err.Number` gets set and `rc` is whatever was there before.
        // Clear Err + seed rc with a sentinel so we can tell "ws.Run never ran" from
        // "ws.Run ran and powershell exited with code N".
        vbs.Append("  Err.Clear\r\n");
        // psExe is a VBS variable resolved above (pwsh.exe 7 if installed, else
        // powershell.exe 5.1). Concatenate it into the command line so the
        // custom action never hard-codes a runtime at MSI build time.
        //
        // The script runs through cmd.exe so stdout+stderr can be redirected to a
        // sidecar log: ws.Run goes straight to CreateProcess, which has no
        // redirection of its own, and the hidden window means console output is
        // otherwise lost forever. The log is echoed into Session.Log (visible in
        // the msiexec /l*v log) and persisted under ManagedInstalls\Logs so
        // endpoint tooling (e.g. an installcheck_script) can surface the last
        // attempt's output into the managing client's run log.
        vbs.Append("  q = Chr(34)\r\n");
        vbs.Append("  logFile = tmpFile & \".log\"\r\n");
        vbs.Append("  cmdLine = \"cmd.exe /c \" & q & q & psExe & q & \" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \" & q & tmpFile & q & \" > \" & q & logFile & q & \" 2>&1\" & q\r\n");
        vbs.Append("  rc = ws.Run(cmdLine, 0, True)\r\n");
        vbs.Append("  If Err.Number <> 0 Then\r\n");
        vbs.Append($"    Session.Log \"{actionName}: failed to start powershell: \" & Err.Number & \" - \" & Err.Description\r\n");
        vbs.Append("  Else\r\n");
        vbs.Append($"    Session.Log \"{actionName}: powershell exit code \" & rc\r\n");
        vbs.Append("  End If\r\n");
        // Echo captured script output (capped) and persist a copy for endpoint tooling.
        vbs.Append("  If fso.FileExists(logFile) Then\r\n");
        vbs.Append("    Set logStream = fso.OpenTextFile(logFile, 1)\r\n");
        vbs.Append("    lineCount = 0\r\n");
        vbs.Append("    Do While Not logStream.AtEndOfStream And lineCount < 200\r\n");
        vbs.Append("      logLine = logStream.ReadLine\r\n");
        vbs.Append($"      Session.Log \"{actionName} | \" & logLine\r\n");
        vbs.Append("      lineCount = lineCount + 1\r\n");
        vbs.Append("    Loop\r\n");
        vbs.Append($"    If Not logStream.AtEndOfStream Then Session.Log \"{actionName} | ... output truncated at 200 lines\"\r\n");
        vbs.Append("    logStream.Close\r\n");
        // ProductName feeds a filename, so strip the characters NTFS rejects.
        vbs.Append("    prodName = cimianProdName\r\n");
        vbs.Append("    For Each ch In Array(\"\\\", \"/\", \":\", \"*\", \"?\", q, \"<\", \">\", \"|\")\r\n");
        vbs.Append("      prodName = Replace(prodName, ch, \"_\")\r\n");
        vbs.Append("    Next\r\n");
        // CreateFolder cannot create nested paths, so build each level. Failures
        // here (and in CopyFile) are non-fatal: Session.Log already has the
        // output, and the temp log is only removed once the copy succeeded.
        vbs.Append("    logDir = ws.ExpandEnvironmentStrings(\"%ProgramData%\") & \"\\ManagedInstalls\"\r\n");
        vbs.Append("    If Not fso.FolderExists(logDir) Then fso.CreateFolder logDir\r\n");
        vbs.Append("    logDir = logDir & \"\\Logs\"\r\n");
        vbs.Append("    If Not fso.FolderExists(logDir) Then fso.CreateFolder logDir\r\n");
        vbs.Append("    Err.Clear\r\n");
        vbs.Append($"    fso.CopyFile logFile, logDir & \"\\cimipkg-\" & prodName & \"-{actionName}.log\", True\r\n");
        vbs.Append("    If Err.Number = 0 Then\r\n");
        vbs.Append("      fso.DeleteFile logFile\r\n");
        vbs.Append("    Else\r\n");
        vbs.Append($"      Session.Log \"{actionName}: could not persist log copy: \" & Err.Description\r\n");
        vbs.Append("      Err.Clear\r\n");
        vbs.Append("    End If\r\n");
        vbs.Append("  End If\r\n");
        vbs.Append("  If fso.FileExists(tmpFile) Then fso.DeleteFile tmpFile\r\n");
        vbs.Append("End If\r\n");
        // A non-zero script exit must fail the action (and with it the install)
        // so the managing client records a real failure instead of a phantom
        // success. rc = -1 covers both "staging failed, script never ran" and
        // "ws.Run never started powershell". Uninstall scripts stay
        // best-effort: a broken uninstall script should not wedge removal.
        vbs.Append("If cimianPhase = \"install\" And rc <> 0 Then\r\n");
        vbs.Append($"  Session.Log \"{actionName}: script failed (exit \" & rc & \") - failing action\"\r\n");
        vbs.Append("  On Error GoTo 0\r\n");
        vbs.Append($"  Err.Raise vbObjectError + 27, \"{actionName}\", \"PowerShell script exited \" & rc\r\n");
        vbs.Append("End If\r\n");

        return vbs.ToString();
    }


    /// <summary>
    /// Signs a combined PowerShell script at build time so the temp .ps1 written
    /// by the VBScript custom action at install time already carries a valid
    /// Authenticode signature. This prevents EDR/AV false positives from unsigned
    /// scripts executing out of %TEMP%, even when the parent process is msiexec.
    ///
    /// The signature block (<c># SIG # Begin signature block</c> … <c># SIG # End
    /// signature block</c>) is appended to the script content before it is
    /// base64-encoded into the VBS, so the round-trip is transparent to
    /// <see cref="BuildScriptActionVbs"/>.
    /// </summary>
    private string SignScriptContent(string scriptContent, BuildInfo buildInfo)
    {
        if (string.IsNullOrEmpty(buildInfo.SigningCertificate) &&
            string.IsNullOrEmpty(buildInfo.SigningThumbprint))
            return scriptContent;

        // Don't bother signing placeholder stubs
        if (scriptContent.StartsWith("# No "))
            return scriptContent;

        var tmpPath = Path.Combine(Path.GetTempPath(), $"cimipkg-sign-{Guid.NewGuid():N}.ps1");
        try
        {
            File.WriteAllText(tmpPath, scriptContent, new System.Text.UTF8Encoding(true));
            _codeSigner.SignPowerShellScript(tmpPath, buildInfo.SigningCertificate, buildInfo.SigningThumbprint);
            _logger.LogInformation("Signed embedded script: {TmpPath}", Path.GetFileName(tmpPath));
            return File.ReadAllText(tmpPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sign embedded script — embedding unsigned");
            return scriptContent;
        }
        finally
        {
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); }
            catch { /* best-effort cleanup */ }
        }
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
    /// Build one CAB per cabinet segment via makecab.exe, then embed each CAB
    /// as a named stream inside the MSI (stream name == cabinet name, matching
    /// the Media table rows written by <see cref="WritePayloadTables"/>).
    /// File-key naming inside each CAB must match the File table keys
    /// (e.g., "F_hello_txt") — both come from <see cref="PlanCabinetSegments"/>
    /// so they cannot drift.
    /// </summary>
    private void EmbedPayloadCabs(string msiPath, IReadOnlyList<CabinetSegment> segments)
    {
        if (segments.Count == 0) return;

        var tempDir = Path.Combine(Path.GetTempPath(), $"cimipkg_cab_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Step 1: build each cabinet via its own makecab invocation.
            // Each segment gets its own DDF + makecab run so cabinets are
            // independent (no cross-cabinet file spanning) — this is the
            // standard MSI multi-disk layout used by Office, Visual Studio,
            // the Windows SDK, etc.
            foreach (var seg in segments)
            {
                BuildOneCabinet(tempDir, seg);
            }

            // Step 2: open the MSI once and embed every cabinet as a stream.
            using var db = new Database(msiPath, DatabaseOpenMode.Direct);
            using var view = db.OpenView("SELECT `Name`, `Data` FROM `_Streams`");
            view.Execute();

            long totalCabBytes = 0;
            int totalFiles = 0;
            foreach (var seg in segments)
            {
                var cabPath = Path.Combine(tempDir, seg.CabinetName);
                var cabBytes = new FileInfo(cabPath).Length;
                totalCabBytes += cabBytes;
                totalFiles += seg.Files.Count;

                using var record = new Record(2);
                record.SetString(1, seg.CabinetName);
                record.SetStream(2, cabPath);
                view.Modify(ViewModifyMode.Assign, record);

                _logger.LogDebug(
                    "Embedded cabinet '{CabName}': {Files} files, {Bytes:N0} bytes",
                    seg.CabinetName, seg.Files.Count, cabBytes);
            }

            db.Commit();

            _logger.LogInformation(
                "CAB(s) embedded in MSI ({Cabs} cabinet(s), {Files} files, {Bytes:N0} bytes total)",
                segments.Count, totalFiles, totalCabBytes);
        }
        finally
        {
            // Cleanup temp directory
            try { Directory.Delete(tempDir, true); } catch { }
        }
    }

    /// <summary>
    /// Run makecab.exe once for a single cabinet segment, producing
    /// <paramref name="tempDir"/>\{seg.CabinetName} on disk.
    /// </summary>
    private void BuildOneCabinet(string tempDir, CabinetSegment seg)
    {
        var ddfBaseName = Path.GetFileNameWithoutExtension(seg.CabinetName);
        var ddfPath = Path.Combine(tempDir, $"{ddfBaseName}.ddf");
        var ddf = new StringBuilder();
        ddf.AppendLine(".OPTION EXPLICIT");
        ddf.AppendLine($".Set CabinetNameTemplate={seg.CabinetName}");
        ddf.AppendLine($".Set DiskDirectoryTemplate={tempDir}");
        ddf.AppendLine(".Set Cabinet=on");
        ddf.AppendLine(".Set Compress=on");
        ddf.AppendLine(".Set CompressionType=MSZIP");
        // MaxDiskSize=0 means "no limit" within THIS cabinet — we drive
        // chunking ourselves at the file-group level (see PlanCabinetSegments)
        // so makecab never needs to split mid-file across cabinets.
        ddf.AppendLine(".Set MaxDiskSize=0");
        ddf.AppendLine(".Set RptFileName=nul");
        ddf.AppendLine(".Set InfFileName=nul");
        ddf.AppendLine(".Set UniqueFiles=off");

        foreach (var pf in seg.Files)
        {
            // makecab DDF syntax: "sourcePath" "destinationNameInCab"
            ddf.AppendLine($"\"{pf.SourcePath}\" \"{pf.FileKey}\"");
        }
        File.WriteAllText(ddfPath, ddf.ToString());

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
        // Drain both streams concurrently to avoid the deadlock where makecab
        // fills its stderr pipe while we're synchronously waiting on stdout
        // (or vice versa). This bit large payloads on arm64 reliably.
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        var output = stdoutTask.GetAwaiter().GetResult();
        var error = stderrTask.GetAwaiter().GetResult();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"makecab.exe failed (exit {process.ExitCode}) building '{seg.CabinetName}': {error}{output}");
        }

        var cabPath = Path.Combine(tempDir, seg.CabinetName);
        if (!File.Exists(cabPath))
        {
            throw new FileNotFoundException($"CAB file not created at: {cabPath}");
        }

        _logger.LogDebug("Built cabinet '{CabName}' ({Bytes:N0} bytes)",
            seg.CabinetName, new FileInfo(cabPath).Length);
    }

    private static string EscSql(string value) => value.Replace("'", "''");

    /// <summary>
    /// Pad an MSI product version to the 4-part major.minor.build.revision shape
    /// required by the File table Version column. Inputs are trusted MSI versions
    /// produced by <see cref="MsiVersionConverter.Convert"/>, so we only handle
    /// the 2-part and 3-part shapes cimipkg actually emits today.
    /// </summary>
    private static string NormalizeToFourPartVersion(string version)
    {
        if (string.IsNullOrWhiteSpace(version)) return "0.0.0.0";
        var parts = version.Split('.');
        return parts.Length switch
        {
            1 => $"{parts[0]}.0.0.0",
            2 => $"{parts[0]}.{parts[1]}.0.0",
            3 => $"{parts[0]}.{parts[1]}.{parts[2]}.0",
            _ => $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}",
        };
    }

    /// <summary>
    /// Create nested Directory rows for each segment of <paramref name="relativeDir"/>
    /// (forward- or back-slash separated, relative to INSTALLDIR). Reuses previously
    /// created rows via <paramref name="cache"/>. Returns the Directory identifier of
    /// the deepest segment.
    /// </summary>
    private static string EnsureDirectoryChain(
        Database db,
        Dictionary<string, string> cache,
        string? relativeDir)
    {
        if (string.IsNullOrEmpty(relativeDir))
            return cache[string.Empty];

        var segments = relativeDir.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        var cumulative = string.Empty;
        var parentId = cache[string.Empty];

        foreach (var segment in segments)
        {
            cumulative = cumulative.Length == 0 ? segment : $"{cumulative}/{segment}";
            if (cache.TryGetValue(cumulative, out var existing))
            {
                parentId = existing;
                continue;
            }

            var dirId = $"D_{SanitizeIdentifier(cumulative)}";
            if (dirId.Length > 72)
                dirId = $"D_{Guid.NewGuid():N}";

            db.Execute(
                $"INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) VALUES ('{EscSql(dirId)}', '{EscSql(parentId)}', '{EscSql(segment)}')");

            cache[cumulative] = dirId;
            parentId = dirId;
        }

        return parentId;
    }

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
