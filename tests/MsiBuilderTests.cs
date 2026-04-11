using System;
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
        // 60 KB PowerShell source -> ~120 KB UTF-16 -> ~160 KB base64.
        // Still has to chunk down to <1000 char lines.
        var huge = BuildLargePowerShellScript(60_000);

        var vbs = MsiBuilder.BuildScriptActionVbs("CimianPreinstall", huge);

        AssertAllLinesUnderLimit(vbs);
    }

    [Fact]
    public void BuildScriptActionVbs_RoundTrip_PreservesScriptContentExactly()
    {
        // Pick a script with characters that would otherwise need escaping in VBS
        // string literals (quotes, backslashes, UTF-16 surrogates, newlines).
        var original =
            "# Cimian postinstall\r\n" +
            "$path = 'C:\\Program Files\\Foo\\bar.exe'\r\n" +
            "Write-Host \"Installing to $path\"\r\n" +
            "if (Test-Path $path) { Write-Host 'already there' }\r\n" +
            "Get-ScheduledTask | Where-Object { $_.Name -eq 'X' }\r\n" +
            // Some unicode to make sure UTF-16 survives intact.
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

        // Both the fallback and the upgrade paths must be in the generated VBS.
        Assert.Contains(
            "psExe = \"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\"",
            vbs);
        Assert.Contains(
            "fso.FileExists(\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\")",
            vbs);
        Assert.Contains(
            "psExe = \"C:\\Program Files\\PowerShell\\7\\pwsh.exe\"",
            vbs);
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
}
