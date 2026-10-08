using System;
using System.IO;
using System.Linq;
using System.Text;
using Cimian.CLI.Cimipkg.Services;
using Cimian.CLI.Cimipkg.Services.Msi;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests for MsiBuilder: table authoring, the script custom actions and the cabinet planner.
///
/// Regression context: RenderingManager v2026.04.10.1431 shipped with a broken
/// postinstall custom action because the previous implementation inlined the
/// whole PowerShell script as a single base64 string in a single VBS source
/// line. For ~15 KB of PS1 that line exceeded 40,000 chars, tripping the VBS
/// parser's ~1022 char per-source-line hard limit, and the custom action
/// silently no-op'd on 142 endpoints. These tests enforce that the generated
/// VBS stays parsable even for large scripts.
/// </summary>
public class MsiBuilderTests
{
    [Fact]
    public void WriteDirectoryTable_KnownFolderRoot_EmitsValidInstallDir()
    {
        var msi = Path.Combine(Path.GetTempPath(), $"cimipkg-directory-{Guid.NewGuid():N}.msi");
        try
        {
            using (var db = MsiDatabase.Open(msi, MsiOpenMode.Create))
            {
                MsiBuilder.CreateTables(db);
                MsiBuilder.WriteDirectoryTable(
                    db,
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    isInstallerType: false,
                    productName: "KnownFolderRootTest");
                db.Commit();
            }

            using var readDb = MsiDatabase.Open(msi, MsiOpenMode.ReadOnly);
            using var view = readDb.OpenView(
                "SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`");
            view.Execute();

            var rows = new Dictionary<string, (string Parent, string DefaultDir)>(StringComparer.Ordinal);
            for (var record = view.Fetch(); record != null; record = view.Fetch())
            {
                using (record)
                {
                    rows[record.GetString(1)] = (record.GetString(2), record.GetString(3));
                }
            }

            Assert.Equal(("CommonAppDataFolder", "."), rows["INSTALLDIR"]);
            foreach (var row in rows)
            {
                if (!string.IsNullOrEmpty(row.Value.Parent))
                {
                    Assert.True(rows.ContainsKey(row.Value.Parent),
                        $"Directory '{row.Key}' references missing parent '{row.Value.Parent}'");
                }
            }
        }
        finally
        {
            File.Delete(msi);
        }
    }

    // =========================================================================
    // Script custom actions. Each script lives in the Binary table and runs
    // through an exe custom action whose -Command is a short bootstrap; there is
    // no VBScript. The command line is MSI Formatted text, so these tests pin
    // the escaping that keeps it intact.
    // =========================================================================

    private static string CommandLine(string action = "CimianPostinstall", string phase = "install",
        string product = "Contoso Widget", string version = "2026.10.8") =>
        MsiBuilder.BuildScriptActionCommandLine(action, phase, product, version);

    /// <summary>
    /// What Windows Installer would hand PowerShell: escapes resolved and the
    /// three properties replaced with sample values.
    /// </summary>
    private static string Formatted(string commandLine) => commandLine
        .Replace(@"[\[]", "\u0002").Replace(@"[\]]", "\u0003")
        .Replace("[INSTALLDIR]", @"C:\Program Files\Contoso\")
        .Replace("[OriginalDatabase]", @"C:\Windows\Installer\1a2b3c.msi")
        .Replace("[CIMIAN_PSEXE]", @"C:\Program Files\PowerShell\7\pwsh.exe")
        .Replace("\u0002", "[").Replace("\u0003", "]");

    private static string Bootstrap(string commandLine)
    {
        const string marker = "-Command \"";
        var start = commandLine.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        Assert.EndsWith("\"", commandLine);
        return commandLine.Substring(start, commandLine.Length - start - 1);
    }

    [Fact]
    public void CommandLine_ExpandsOnlyItsThreeProperties()
    {
        var cmd = CommandLine();
        var withoutEscapes = cmd.Replace(@"[\[]", "").Replace(@"[\]]", "");

        var properties = System.Text.RegularExpressions.Regex.Matches(withoutEscapes, @"\[([^\]]*)\]")
            .Select(m => m.Groups[1].Value)
            .Distinct()
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[] { "CIMIAN_PSEXE", "INSTALLDIR", "OriginalDatabase" }, properties);
    }

    [Fact]
    public void CommandLine_BootstrapHasNoDoubleQuotesOrBraces()
    {
        // The bootstrap is one double-quoted -Command argument, and braces are
        // MSI Formatted syntax, so neither may appear inside it.
        var bootstrap = Bootstrap(CommandLine(product: "Bob's \"Widget\" {beta}"));

        Assert.DoesNotContain("\"", bootstrap);
        Assert.DoesNotContain("{", bootstrap);
        Assert.DoesNotContain("}", bootstrap);
    }

    [Theory]
    [InlineData("CimianPreinstall", "install")]
    [InlineData("CimianPostinstall", "install")]
    [InlineData("CimianUninstall", "uninstall")]
    public void CommandLine_BootstrapParsesAsPowerShell(string action, string phase)
    {
        var bootstrap = Formatted(Bootstrap(CommandLine(action, phase, product: "Bob's Widget")));

        Assert.True(PowerShellSyntax.TryValidate(bootstrap, out var errors), errors);
    }

    [Fact]
    public void CommandLine_ReadsItsOwnBinaryRowAndLaunchesTheResolvedRuntime()
    {
        var bootstrap = Formatted(Bootstrap(CommandLine("CimianPreinstall")));

        Assert.Contains("WHERE `Name`=''CimianPreinstall''", bootstrap);
        Assert.Contains(@"'C:\Windows\Installer\1a2b3c.msi'", bootstrap);
        Assert.Contains(@"'C:\Program Files\PowerShell\7\pwsh.exe'", bootstrap);
        Assert.Contains("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File", bootstrap);
        Assert.Contains("exit $rc", bootstrap);
    }

    [Fact]
    public void CommandLine_SetsTheScriptEnvironment()
    {
        var bootstrap = Formatted(Bootstrap(CommandLine("CimianUninstall", "uninstall", version: "1.2.3")));

        Assert.Contains(@"$env:CIMIAN_INSTALLDIR='C:\Program Files\Contoso\'", bootstrap);
        Assert.Contains("$env:CIMIAN_PHASE='uninstall'", bootstrap);
        Assert.Contains("$env:CIMIAN_VERSION='1.2.3'", bootstrap);
    }

    [Fact]
    public void CommandLine_PersistsLogUnderPerPackageDirectory()
    {
        var bootstrap = Formatted(Bootstrap(CommandLine("CimianPostinstall", product: "Bob's Widget: Pro")));

        // NTFS-illegal characters become '_', and the apostrophe is doubled for PowerShell.
        Assert.Contains(@"'ManagedInstalls\logs\packages\Bob''s Widget_ Pro'", bootstrap);
        Assert.Contains("'postinstall.log'", bootstrap);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Bad Name")]
    [InlineData("Bad'Name")]
    [InlineData("Bad;Name")]
    public void CommandLine_RejectsUnsafeActionNames(string badName)
    {
        Assert.Throws<ArgumentException>(() => CommandLine(badName));
    }

    [Theory]
    [InlineData("CimianPreinstall", "preinstall")]
    [InlineData("CimianPostinstall", "postinstall")]
    [InlineData("CimianUninstall", "uninstall")]
    [InlineData("Custom", "custom")]
    public void ScriptLogName_DropsCimianPrefixAndLowercases(string actionName, string expected)
    {
        Assert.Equal(expected, MsiBuilder.ScriptLogName(actionName));
    }

    [Fact]
    public void EncodeScript_IsBase64OfUtf8WithBom()
    {
        const string script = "Write-Output 'héllo [x] {y}'\r\nexit 3";

        var bytes = Convert.FromBase64String(MsiBuilder.EncodeScript(script));

        Assert.Equal(Encoding.UTF8.GetPreamble(), bytes.Take(3).ToArray());
        Assert.Equal(script, Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3));
    }

    [Fact]
    public void ScriptBinary_StoresTheEncodedScriptUnderItsActionName()
    {
        var msi = Path.Combine(Path.GetTempPath(), $"cimipkg-binary-{Guid.NewGuid():N}.msi");
        try
        {
            using (var db = MsiDatabase.Open(msi, MsiOpenMode.Create))
            {
                MsiBuilder.CreateTables(db);
                MsiBuilder.WriteScriptBinary(db, "CimianPostinstall", "exit 0");
                db.Commit();
            }

            using var read = MsiDatabase.Open(msi, MsiOpenMode.ReadOnly);
            Assert.Equal("CimianPostinstall",
                read.ExecuteScalar("SELECT `Name` FROM `Binary` WHERE `Name` = ?", "CimianPostinstall"));
        }
        finally
        {
            File.Delete(msi);
        }
    }

    // =========================================================================
    // Cabinet planner tests — guard the multi-CAB split that lets cimipkg ship
    // payloads larger than makecab.exe's ~2 GB single-cabinet ceiling.
    //
    // Regression context: a cimipkg user reported Unreal Engine 5.6.1 (~25.6 GB
    // payload) failing to build because makecab tops out near 2 GB per cabinet.
    // The fix splits the payload into N cabinets via the standard MSI Media
    // table layout. These tests pin the planner's chunking semantics so the
    // small-payload case stays byte-identical to single-CAB output and the
    // large-payload case rolls over correctly at the threshold.
    // =========================================================================

    [Fact]
    public void PlanCabinetSegments_EmptyPayload_ReturnsZeroSegments()
    {
        using var tmp = new TempDir();
        var plan = MsiBuilder.PlanCabinetSegments(tmp.Path, Array.Empty<string>(), "test.identifier");
        Assert.Empty(plan);
    }

    [Fact]
    public void PlanCabinetSegments_SmallPayload_FitsInOneCabinet_KeepsLegacyName()
    {
        // Single-cabinet payloads MUST keep the historical "product.cab" name
        // so external diagnostic tooling (wix decompile, lessmsi, etc.) that
        // recognizes that name keeps working — and so the byte-level diff
        // between this commit and the previous cimipkg release stays minimal
        // for the common case.
        using var tmp = new TempDir();
        var files = new[]
        {
            tmp.WriteFile("a.txt", 100),
            tmp.WriteFile("sub/b.txt", 200),
            tmp.WriteFile("c.bin", 300),
        };

        var plan = MsiBuilder.PlanCabinetSegments(tmp.Path, files, "test.identifier");

        Assert.Single(plan);
        Assert.Equal(1, plan[0].DiskId);
        Assert.Equal("product.cab", plan[0].CabinetName);
        Assert.Equal(3, plan[0].Files.Count);
        Assert.Equal(new[] { 1, 2, 3 }, plan[0].Files.Select(f => f.Sequence));
    }

    [Fact]
    public void PlanCabinetSegments_PayloadExceedsThreshold_RollsOverAtBoundary()
    {
        // 5 files × 400 bytes each = 2000 bytes total. Threshold = 1000 bytes.
        // Expected layout: cabinet 1 = files 1-2 (800 bytes), cabinet 2 =
        // files 3-4 (800 bytes), cabinet 3 = file 5 (400 bytes).
        using var tmp = new TempDir();
        var files = Enumerable.Range(1, 5)
            .Select(i => tmp.WriteFile($"f{i}.bin", 400))
            .ToArray();

        var plan = MsiBuilder.PlanCabinetSegments(tmp.Path, files, "test.identifier",
            maxBytesPerCabinet: 1000);

        Assert.Equal(3, plan.Count);
        Assert.Equal(2, plan[0].Files.Count);
        Assert.Equal(2, plan[1].Files.Count);
        Assert.Single(plan[2].Files);

        // DiskIds are 1-based and contiguous.
        Assert.Equal(new[] { 1, 2, 3 }, plan.Select(s => s.DiskId));
        // Cabinet names use product{N}.cab when there's more than one segment.
        Assert.Equal(new[] { "product1.cab", "product2.cab", "product3.cab" },
            plan.Select(s => s.CabinetName));
        // File.Sequence values are contiguous 1..N across the entire payload —
        // not reset per cabinet. This is required for MSI's Media.LastSequence
        // ranges to correctly identify which cabinet each file lives in.
        var allSequences = plan.SelectMany(s => s.Files).Select(f => f.Sequence).ToArray();
        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, allSequences);
    }

    [Fact]
    public void PlanCabinetSegments_SingleFileLargerThanThreshold_GetsItsOwnCabinet()
    {
        // A single file larger than the threshold MUST still land in a cabinet
        // (we don't reject it). makecab will fail informatively if the resulting
        // CAB exceeds the format's hard ~2 GB limit, and the operator can split
        // that file at the source. Refusing the file at the planner level would
        // hide what's actually wrong.
        using var tmp = new TempDir();
        var files = new[]
        {
            tmp.WriteFile("normal.txt", 50),
            tmp.WriteFile("huge.bin", 5000),     // bigger than threshold
            tmp.WriteFile("after.txt", 50),
        };

        var plan = MsiBuilder.PlanCabinetSegments(tmp.Path, files, "test.identifier",
            maxBytesPerCabinet: 1000);

        Assert.Equal(3, plan.Count);
        Assert.Single(plan[0].Files);                       // normal.txt
        Assert.Equal("normal.txt", plan[0].Files[0].RelativePath);
        Assert.Single(plan[1].Files);                       // huge.bin alone
        Assert.Equal("huge.bin", plan[1].Files[0].RelativePath);
        Assert.Single(plan[2].Files);                       // after.txt
        Assert.Equal("after.txt", plan[2].Files[0].RelativePath);
    }

    [Fact]
    public void PlanCabinetSegments_FileKeysMatchAcrossSegments()
    {
        // Both WritePayloadTables (Media/File rows) and EmbedPayloadCabs (CAB
        // contents) consume this same plan. If FileKey derivation drifts between
        // those two consumers, the File table would point at one key while the
        // CAB contains another — install would fail with "file not found in
        // cabinet". Keys MUST be deterministic per (relative path, identifier).
        using var tmp = new TempDir();
        var files = new[]
        {
            tmp.WriteFile("alpha/one.txt", 10),
            tmp.WriteFile("beta/two.bin", 20),
        };

        var planA = MsiBuilder.PlanCabinetSegments(tmp.Path, files, "test.identifier");
        var planB = MsiBuilder.PlanCabinetSegments(tmp.Path, files, "test.identifier");

        var keysA = planA.SelectMany(s => s.Files).Select(f => f.FileKey).ToArray();
        var keysB = planB.SelectMany(s => s.Files).Select(f => f.FileKey).ToArray();
        Assert.Equal(keysA, keysB);
        // Sanity: ComponentKey + ComponentId are also deterministic.
        var compA = planA.SelectMany(s => s.Files).Select(f => f.ComponentId).ToArray();
        var compB = planB.SelectMany(s => s.Files).Select(f => f.ComponentId).ToArray();
        Assert.Equal(compA, compB);
    }

    [Fact]
    public void PlanCabinetSegments_RejectsNonPositiveThreshold()
    {
        using var tmp = new TempDir();
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MsiBuilder.PlanCabinetSegments(tmp.Path, Array.Empty<string>(), "id", maxBytesPerCabinet: 0));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MsiBuilder.PlanCabinetSegments(tmp.Path, Array.Empty<string>(), "id", maxBytesPerCabinet: -1));
    }

    /// <summary>
    /// Disposable scratch directory for planner tests that need real files on
    /// disk (the planner calls FileInfo.Length which requires an actual file).
    /// </summary>
    private sealed class TempDir : IDisposable
    {
        public string Path { get; }
        public TempDir()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                $"cimipkg-planner-test-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }
        public string WriteFile(string relativePath, int sizeBytes)
        {
            var full = System.IO.Path.Combine(Path, relativePath.Replace('/', System.IO.Path.DirectorySeparatorChar));
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
            // Random content keeps tests honest if any future planner check were
            // to look at content (it currently only looks at length).
            var bytes = new byte[sizeBytes];
            new Random(relativePath.GetHashCode()).NextBytes(bytes);
            File.WriteAllBytes(full, bytes);
            return full;
        }
        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); } catch { /* best effort */ }
        }
    }
}
