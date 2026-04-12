using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Cimian.CLI.Cimipkg.Services;

/// <summary>
/// Handles the post-build prompt that offers to run <c>cimiimport</c> on the
/// freshly-built package.
///
/// Design notes:
/// <list type="bullet">
///   <item>
///     If standard input is redirected (CI/CD, piped, non-interactive shell),
///     the prompt is skipped immediately with no blocking. This mirrors the
///     <c>isatty(STDIN_FILENO) == 0</c> fast path in MunkiPkg's Swift
///     implementation.
///   </item>
///   <item>
///     The prompt times out after 60 seconds. On timeout the default answer
///     is "no", matching MunkiPkg's defaultYes=false call-site semantics.
///   </item>
///   <item>
///     <c>cimiimport</c> is launched with stdio inherited from the parent
///     process. It is interactive and prompts the operator for metadata
///     (category, description, etc.), so piping its stdio would break the
///     flow. <c>ProcessStartInfo.RedirectStandard*</c> is left at its default
///     (false) to preserve terminal inheritance.
///   </item>
/// </list>
/// </summary>
public static class ImportPrompter
{
    private const int PromptTimeoutSeconds = 60;
    private const string CimiimportExecutable = "cimiimport.exe";

    /// <summary>
    /// Prompts the operator whether to run <c>cimiimport</c> on the given
    /// package and, if they say yes, shells out to it with inherited stdio.
    /// Does nothing when <paramref name="skipImport"/> is true or when stdin
    /// is not a TTY.
    /// </summary>
    /// <param name="packagePath">Path to the freshly-built package.</param>
    /// <param name="skipImport">When true, suppresses the prompt entirely.</param>
    /// <param name="logger">Logger for status messages.</param>
    public static async Task MaybeRunImportAsync(
        string packagePath,
        bool skipImport,
        ILogger logger)
    {
        if (skipImport)
        {
            return;
        }

        if (Console.IsInputRedirected)
        {
            // Non-interactive shell (CI, pipe, IDE run-config). Silently skip
            // so automated builds don't hang waiting for a stdin answer.
            return;
        }

        var runImport = await PromptYesNoAsync(
            "Do you want to import the new package into the Cimian repo?",
            defaultYes: false,
            TimeSpan.FromSeconds(PromptTimeoutSeconds));

        if (!runImport)
        {
            return;
        }

        RunCimiimport(packagePath, logger);
    }

    /// <summary>
    /// Prompts the user on stdin with a yes/no question. Honors a timeout —
    /// on expiry, returns <paramref name="defaultYes"/>.
    /// </summary>
    /// <remarks>
    /// Public for unit testing. Callers that want the full "skip if CI"
    /// behavior should use <see cref="MaybeRunImportAsync"/> instead.
    /// </remarks>
    public static async Task<bool> PromptYesNoAsync(
        string message,
        bool defaultYes,
        TimeSpan timeout)
    {
        var suffix = defaultYes ? " [Y/n]: " : " [y/N]: ";
        Console.Write(message + suffix);

        var readTask = Task.Run(() =>
        {
            try
            {
                return Console.ReadLine();
            }
            catch (IOException)
            {
                return null;
            }
        });

        var completed = await Task.WhenAny(readTask, Task.Delay(timeout));
        if (completed != readTask)
        {
            Console.WriteLine();
            Console.WriteLine($"Timeout reached ({(int)timeout.TotalSeconds}s). Using default: {(defaultYes ? "Y" : "N")}");
            return defaultYes;
        }

        var response = (await readTask)?.Trim();
        if (string.IsNullOrEmpty(response))
        {
            return defaultYes;
        }

        return IsYes(response);
    }

    /// <summary>
    /// Parses a single-line yes/no answer. Public for unit testing.
    /// Matches "y" / "yes" case-insensitively; anything else is "no".
    /// </summary>
    public static bool IsYes(string response)
    {
        return string.Equals(response, "y", StringComparison.OrdinalIgnoreCase)
            || string.Equals(response, "yes", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Launches <c>cimiimport</c> on the given package with stdio inherited
    /// from the parent process. Does not throw on non-zero exit from the
    /// child — <c>cimiimport</c> has its own error reporting — but does
    /// throw if the process cannot be started at all.
    /// </summary>
    private static void RunCimiimport(string packagePath, ILogger logger)
    {
        var cimiimportPath = ResolveCimiimportPath();
        if (cimiimportPath == null)
        {
            logger.LogWarning(
                "cimiimport not found on PATH or next to cimipkg. Skipping import. " +
                "Install CimianTools or run cimiimport manually: cimiimport \"{PackagePath}\"",
                packagePath);
            return;
        }

        Console.WriteLine();
        logger.LogInformation("Running cimiimport \"{PackagePath}\"", packagePath);
        Console.WriteLine();

        var psi = new ProcessStartInfo
        {
            FileName = cimiimportPath,
            UseShellExecute = false,
            // Stdio intentionally NOT redirected — cimiimport is interactive
            // and prompts for metadata. Inheriting the parent's terminal is
            // load-bearing for the UX.
        };
        psi.ArgumentList.Add(packagePath);

        using var process = Process.Start(psi);
        if (process == null)
        {
            throw new InvalidOperationException($"Failed to start {cimiimportPath}");
        }

        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            logger.LogWarning("cimiimport exited with code {ExitCode}", process.ExitCode);
        }
        else
        {
            logger.LogInformation("Package imported successfully");
        }
    }

    /// <summary>
    /// Locates <c>cimiimport.exe</c>. Search order:
    /// <list type="number">
    ///   <item>Alongside the current cimipkg binary (same release directory).</item>
    ///   <item>On the system PATH.</item>
    /// </list>
    /// Returns null if neither is found.
    /// </summary>
    private static string? ResolveCimiimportPath()
    {
        // Prefer a cimiimport.exe sitting next to cimipkg. CimianTools ships
        // both binaries into the same release directory, so this is the
        // common case and avoids ambiguity when multiple CimianTools
        // releases exist on PATH.
        var cimipkgDir = AppContext.BaseDirectory;
        if (!string.IsNullOrEmpty(cimipkgDir))
        {
            var sibling = Path.Combine(cimipkgDir, CimiimportExecutable);
            if (File.Exists(sibling))
            {
                return sibling;
            }
        }

        // Fall back to PATH lookup.
        var pathVar = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathVar))
        {
            return null;
        }

        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir))
            {
                continue;
            }

            var candidate = Path.Combine(dir, CimiimportExecutable);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }
}
