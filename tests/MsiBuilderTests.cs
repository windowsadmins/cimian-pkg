using System;
using System.IO;
using System.Linq;
using System.Text;
using Cimian.CLI.Cimipkg.Services;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests for MsiBuilder, specifically the VBScript custom action generator.
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
    // VBS parser has a hard limit around 1022 chars per source line. Anything
    // approaching that is a ticking time bomb, so we assert an aggressive
    // safety margin of 1000 chars to leave headroom for the `b64 = b64 & "..."`
    // wrapper overhead.
    private const int VbsPerLineSafeLimit = 1000;

    [Fact]
    public void BuildScriptActionVbs_TinyScript_ProducesValidVbs()
    {
        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", "Write-Host 'hello'");

        AssertAllLinesUnderLimit(vbs);
        Assert.Contains("powershell.exe", vbs);
        Assert.Contains("-File", vbs);
        Assert.Contains("Msxml2.DOMDocument.6.0", vbs);
        Assert.Contains("ADODB.Stream", vbs);
        Assert.Contains("stream.SaveToFile", vbs);
        Assert.Contains("cimian-CimianPostinstall-", vbs);
    }

    [Fact]
    public void BuildScriptActionVbs_LargeScript_StaysUnderVbsParserLimit()
    {
        // RenderingManager's real postinstall is ~15 KB and that's what broke
        // the previous implementation. Go a bit bigger to add safety margin.
        // Note: the script is transported through the VBS as UTF-8 with a BOM
        // (not UTF-16LE), so 20 KB of PS source stays ~20 KB after UTF-8
        // encoding and produces ~27 KB of base64 before chunking.
        var largeScript = BuildLargePowerShellScript(20_000);

        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", largeScript);

        AssertAllLinesUnderLimit(vbs);

        // Sanity: the VBS must actually contain the chunked base64 assignment,
        // not just a single huge line.
        var chunkLines = vbs
            .Replace("\r\n", "\n")
            .Split('\n')
            .Count(l => l.StartsWith("b64 = b64 & \""));
        Assert.True(chunkLines >= 2,
            $"Expected at least 2 base64 chunks for a 20 KB script, got {chunkLines}");
    }

    [Fact]
    public void BuildScriptActionVbs_ExtremelyLargeScript_StillValid()
    {
        // 60 KB PowerShell source -> ~60 KB UTF-8 (with BOM) -> ~80 KB base64.
        // Still has to chunk down to <1000 char lines.
        var huge = BuildLargePowerShellScript(60_000);

        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPreinstall", huge);

        AssertAllLinesUnderLimit(vbs);
    }

    [Fact]
    public void BuildScriptActionVbs_RoundTrip_PreservesScriptContentExactly()
    {
        // Pick a script with characters that would otherwise need escaping in VBS
        // string literals (quotes, backslashes, Unicode via UTF-8, newlines).
        var original =
            "# Cimian postinstall\r\n" +
            "$path = 'C:\\Program Files\\Foo\\bar.exe'\r\n" +
            "Write-Host \"Installing to $path\"\r\n" +
            "if (Test-Path $path) { Write-Host 'already there' }\r\n" +
            "Get-ScheduledTask | Where-Object { $_.Name -eq 'X' }\r\n" +
            // Some unicode to make sure UTF-8 round-trips correctly.
            "# emoji: \u2713 check mark\r\n";

        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", original);

        var reconstructed = ReconstructScriptFromVbs(vbs);
        Assert.Equal(original, reconstructed);
    }

    [Fact]
    public void BuildScriptActionVbs_EmbedsActionNameInTempPath()
    {
        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPreinstall", "exit 0");
        Assert.Contains("\\cimian-CimianPreinstall-", vbs);

        var vbs2 = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", "exit 0");
        Assert.Contains("\\cimian-CimianPostinstall-", vbs2);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad name")]          // space
    [InlineData("bad/name")]          // path separator
    [InlineData("bad\\name")]         // path separator
    [InlineData("bad\"name")]         // quote that would break VBS string literal
    [InlineData("bad;name")]          // VBS statement separator
    [InlineData("..\\escape")]        // directory traversal attempt
    public void BuildScriptActionVbs_RejectsUnsafeActionNames(string badName)
    {
        // actionName is interpolated directly into VBS string literals and the
        // staged temp file path. The method must refuse anything that could
        // break either surface rather than silently producing a corrupted
        // custom action or writing outside %TEMP%.
        var ex = Assert.ThrowsAny<ArgumentException>(
            () => MsiBuilder.BuildScriptActionVbs(badName, "exit 0"));
        Assert.Equal("actionName", ex.ParamName);
    }

    [Fact]
    public void BuildScriptActionVbs_EmitsPwshRuntimeDetection()
    {
        // The custom action must resolve the PowerShell runtime at install time
        // rather than baking a specific path into the MSI at build time. This
        // lets the same cimipkg MSI work on endpoints whether or not
        // PowerShell 7 is installed: pwsh.exe is preferred when present,
        // otherwise it falls back to the 5.1 powershell.exe that ships with
        // every supported Windows image.
        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", "exit 0");

        // Paths must be resolved via env expansion at install time, not hardcoded
        // to C:\ — ensures the MSI works regardless of OS drive letter.
        Assert.Contains("ws.ExpandEnvironmentStrings(\"%SystemRoot%\")", vbs);
        Assert.Contains("ws.ExpandEnvironmentStrings(\"%ProgramW6432%\")", vbs);
        // Fallback to 5.1 via %SystemRoot%
        Assert.Contains("sysRoot & \"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"", vbs);
        // Upgrade to pwsh 7 via %ProgramW6432%
        Assert.Contains("progFiles & \"\\PowerShell\\7\\pwsh.exe\"", vbs);
        // 7-preview is probed as a courtesy for dev machines.
        Assert.Contains("7-preview", vbs);
    }

    [Fact]
    public void BuildScriptActionVbs_WsRunUsesPsExeVariableNotHardcodedPath()
    {
        // Regression guard: previous revisions interpolated the powershell.exe
        // path as a literal into the ws.Run command line, baking PS 5.1 into
        // every MSI at build time. The resolver-based design must use the
        // runtime-resolved psExe variable instead.
        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPostinstall", "exit 0");

        // The ws.Run line must concatenate psExe, not embed a literal
        // powershell.exe path directly inside the string literal.
        Assert.Contains("ws.Run(\"\"\"\" & psExe & \"\"\"", vbs);

        // And the only literal mentions of the 5.1 path should be the
        // fallback assignment - not an argument to ws.Run.
        var wsRunLines = vbs
            .Replace("\r\n", "\n")
            .Split('\n')
            .Where(l => l.Contains("ws.Run("))
            .ToList();
        Assert.NotEmpty(wsRunLines);
        foreach (var line in wsRunLines)
        {
            Assert.DoesNotContain("WindowsPowerShell\\v1.0\\powershell.exe", line);
            Assert.DoesNotContain("PowerShell\\7\\pwsh.exe", line);
        }
    }

    private static void AssertAllLinesUnderLimit(string vbs)
    {
        var lines = vbs.Replace("\r\n", "\n").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            Assert.True(
                lines[i].Length <= VbsPerLineSafeLimit,
                $"VBS line {i + 1} is {lines[i].Length} chars (limit {VbsPerLineSafeLimit}). " +
                $"This would trip the VBScript parser at install time. " +
                $"Line preview: {lines[i].Substring(0, Math.Min(80, lines[i].Length))}...");
        }
    }

    /// <summary>
    /// Extract the base64 chunks from the generated VBS, decode them, and
    /// rebuild the original PowerShell source. This mirrors what the real
    /// custom action does at install time (via MSXML + ADODB.Stream) so a
    /// passing round-trip proves the whole pipeline preserves script bytes.
    /// </summary>
    private static string ReconstructScriptFromVbs(string vbs)
    {
        var b64 = new StringBuilder();
        foreach (var line in vbs.Replace("\r\n", "\n").Split('\n'))
        {
            // Lines look like: b64 = b64 & "AAAA...ZZZZ"
            const string prefix = "b64 = b64 & \"";
            if (!line.StartsWith(prefix)) continue;
            if (!line.EndsWith("\"")) continue;
            var chunk = line.Substring(prefix.Length, line.Length - prefix.Length - 1);
            b64.Append(chunk);
        }

        var bytes = Convert.FromBase64String(b64.ToString());
        // The VBS reconstructs UTF-8 bytes with a 3-byte BOM prefix. Strip the BOM
        // so the round-trip compares against the caller's original script content,
        // not a BOM-prefixed variant of it.
        var bom = Encoding.UTF8.GetPreamble();
        Assert.True(bytes.Length >= bom.Length, "Emitted payload is smaller than the UTF-8 BOM");
        for (int i = 0; i < bom.Length; i++)
        {
            Assert.Equal(bom[i], bytes[i]);
        }
        return Encoding.UTF8.GetString(bytes, bom.Length, bytes.Length - bom.Length);
    }

    private static string BuildLargePowerShellScript(int approxBytes)
    {
        var sb = new StringBuilder(approxBytes + 1024);
        sb.AppendLine("# Generated test script");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        var line = "Write-Host \"This is a representative postinstall line that does not run but fills space.\"\r\n";
        while (sb.Length < approxBytes)
        {
            sb.Append(line);
        }
        return sb.ToString();
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
