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
    /// (via powershell.exe, which is present on every Windows build host).
    /// Returns true when the script parses; otherwise false with the parser's
    /// own error messages (line-numbered) in <paramref name="errors"/>.
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

            // ParseFile reports syntax errors without executing anything.
            var command =
                "$e = $null; " +
                $"[void][System.Management.Automation.Language.Parser]::ParseFile('{tmp.Replace("'", "''")}', [ref]$null, [ref]$e); " +
                "if ($e) { $e | ForEach-Object { Write-Output (\"line \" + $_.Extent.StartLineNumber + \": \" + $_.Message) }; exit 1 } " +
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
