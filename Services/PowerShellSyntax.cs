using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Cimian.CLI.Cimipkg.Services;

/// <summary>
/// Pack-time PowerShell syntax validation for scripts that will be embedded in
/// an installer. A script that does not parse cannot ever succeed at install
/// time — it fails on every device as an opaque MSI 1603. Catching it here
/// turns a fleet-wide install outage into a single failed build with the parse
/// error and line number in the CI log (field incident 2026-07-21: placeholder
/// substitution corrupted param([string]$Path) in ReportMate's preinstall and
/// every device rejected the MSI).
/// </summary>
public static class PowerShellSyntax
{
    /// <summary>
    /// Parses <paramref name="content"/> with the real PowerShell parser
    /// (via powershell.exe, which is present on every Windows build host),
    /// then checks the parsed AST for an assignment that lost its <c>$</c>.
    /// Returns true when the script passes both; otherwise false with the
    /// line-numbered findings in <paramref name="errors"/>.
    /// Returns true with a note in <paramref name="errors"/> when no
    /// PowerShell engine is available, so validation never blocks a build on
    /// a host that cannot run it.
    /// </summary>
    public static bool TryValidate(string content, out string errors)
    {
        errors = string.Empty;
        if (string.IsNullOrWhiteSpace(content))
        {
            return true;
        }

        var psExe = FindPowerShell();
        if (psExe == null)
        {
            errors = "PowerShell engine not found; syntax validation skipped";
            return true;
        }

        var tmp = Path.Combine(Path.GetTempPath(), $"cimipkg-validate-{Guid.NewGuid():N}.ps1");
        try
        {
            File.WriteAllText(tmp, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

            // ParseFile reports syntax errors without executing anything. A
            // script that parses is then walked for statements that are legal
            // grammar but cannot be what the author meant (see BareAssignmentCheck).
            var command =
                "$e = $null; " +
                $"$ast = [System.Management.Automation.Language.Parser]::ParseFile('{tmp.Replace("'", "''")}', [ref]$null, [ref]$e); " +
                "if ($e) { $e | ForEach-Object { Write-Output (\"line \" + $_.Extent.StartLineNumber + \": \" + $_.Message) }; exit 1 } " +
                BareAssignmentCheck +
                "exit 0";

            var psi = new ProcessStartInfo
            {
                FileName = psExe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command");
            psi.ArgumentList.Add(command);

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                errors = "PowerShell engine failed to start; syntax validation skipped";
                return true;
            }

            var stdout = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(60_000);
            if (!proc.HasExited)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                errors = "PowerShell syntax validation timed out; skipped";
                return true;
            }

            if (proc.ExitCode == 0)
            {
                return true;
            }

            errors = stdout.Trim();
            return false;
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }

    /// <summary>
    /// PowerShell parses <c>word = value</c> as a call to a command named
    /// <c>word</c> with the arguments <c>=</c> and <c>value</c>, so an
    /// assignment that lost its <c>$</c> (a placeholder substitution that
    /// consumed <c>$x64</c> and left <c>x64 = ...</c>) passes the parser and
    /// only fails on the device, at install time. This walks the AST for a
    /// pipeline that opens with a bare-word command followed by a bare word
    /// starting with <c>=</c> (or <c>+=</c>, <c>-=</c>, ...), or whose bare
    /// command name itself contains the <c>=</c> (<c>x64='v'</c> and
    /// <c>x64=$v</c> tokenize as one word), and fails when the name before
    /// the <c>=</c> is neither a function defined in the script nor a
    /// command the build host resolves.
    /// Expects <c>$ast</c> to hold the parsed script; writes
    /// <c>line N: ...</c> lines and exits 1 on a finding.
    /// </summary>
    private const string BareAssignmentCheck =
        "$L = [System.Management.Automation.Language.StringConstantType]::BareWord; " +
        "$defined = @{}; " +
        "foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { $defined[$f.Name] = $true } " +
        "$bad = @(); " +
        "foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) { " +
        "  $p = $c.Parent; " +
        "  if (-not ($p -is [System.Management.Automation.Language.PipelineAst]) -or $p.PipelineElements[0] -ne $c) { continue } " +
        "  $el = $c.CommandElements; " +
        "  $n0 = $el[0]; " +
        "  if (-not ($n0 -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or $n0.StringConstantType -ne $L) { continue } " +
        "  $name = $n0.Value; " +
        "  $bare = $null; " +
        "  if ($name -match '^([^=]+?)[-+*/%]?=') { $bare = $Matches[1] } " +
        "  elseif ($el.Count -ge 2) { " +
        "    $n1 = $el[1]; " +
        "    if (($n1 -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n1 -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and $n1.StringConstantType -eq $L -and $n1.Extent.Text -match '^[-+*/%]?=') { $bare = $name } " +
        "  } " +
        "  if (-not $bare) { continue } " +
        "  if ($defined.ContainsKey($bare)) { continue } " +
        "  if ($bare -notmatch '[*?\\[\\]]' -and (Get-Command -Name $bare -ErrorAction SilentlyContinue)) { continue } " +
        "  $bad += (\"line \" + $c.Extent.StartLineNumber + \": '\" + $bare + \" =' calls a command named '\" + $bare + \"', which is not a known command; an assignment needs '$\" + $bare + \"' (check for a placeholder substitution that consumed the '$')\") " +
        "} " +
        "if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Output $_ }; exit 1 } ";

    private static string? FindPowerShell()
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (!string.IsNullOrEmpty(systemRoot))
        {
            var winPs = Path.Combine(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            if (File.Exists(winPs))
            {
                return winPs;
            }
        }

        // pwsh on PATH (non-Windows dev hosts, containers)
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var name in new[] { "pwsh.exe", "pwsh" })
            {
                var candidate = Path.Combine(dir.Trim(), name);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }
}
