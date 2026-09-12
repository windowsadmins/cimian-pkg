using System;
using System.Diagnostics;

namespace Cimian.CLI.Cimipkg.Services;

/// <summary>
/// Runs a build tool and refuses to wait on it forever.
/// </summary>
/// <remarks>
/// Two mistakes are easy to make when shelling out, and this type exists so they
/// are made in one place instead of at every call site.
///
/// The first is draining the streams synchronously before waiting:
///
///     var output = process.StandardOutput.ReadToEnd();
///     var error  = process.StandardError.ReadToEnd();
///     process.WaitForExit();
///
/// ReadToEnd on stdout returns only when that pipe closes, so a tool that fills
/// its stderr buffer in the meantime blocks on the write while we block on the
/// read, and neither side moves again. Both streams have to be drained
/// concurrently.
///
/// The second is a wait with no deadline. A signing call that cannot reach a
/// timestamp authority, or a prompt that is quietly waiting on stdin, then hangs
/// the build indefinitely: the agent job sits until its own timeout and reports
/// nothing useful about where it stopped.
/// </remarks>
internal static class ProcessRunner
{
    /// <summary>Generous by build-tool standards; nothing here should take minutes.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(5);

    public sealed record Result(int ExitCode, string Output, string Error, bool TimedOut);

    /// <summary>
    /// Start <paramref name="psi"/>, drain both streams, and wait up to
    /// <paramref name="timeout"/>. On timeout the process tree is killed and
    /// <see cref="Result.TimedOut"/> is set; whatever was captured is returned.
    /// </summary>
    public static Result Run(ProcessStartInfo psi, TimeSpan? timeout = null, string? label = null)
    {
        var deadline = timeout ?? DefaultTimeout;

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {label ?? psi.FileName}");

        // Start both reads before waiting so the child can never block writing to
        // a full pipe while we are blocked reading the other one.
        var stdout = psi.RedirectStandardOutput ? process.StandardOutput.ReadToEndAsync() : null;
        var stderr = psi.RedirectStandardError ? process.StandardError.ReadToEndAsync() : null;

        if (!process.WaitForExit((int)deadline.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { }

            return new Result(
                ExitCode: -1,
                Output: SafeResult(stdout),
                Error: $"{label ?? psi.FileName} did not exit within {deadline.TotalSeconds:N0}s and was killed.",
                TimedOut: true);
        }

        return new Result(process.ExitCode, SafeResult(stdout), SafeResult(stderr), TimedOut: false);
    }

    // After the process has exited the pipes are closed, so these complete
    // promptly. Wrapped anyway: a killed process can leave a read faulted, and a
    // lost tail of output must not turn into a different exception than the one
    // the caller is about to report.
    private static string SafeResult(System.Threading.Tasks.Task<string>? read)
    {
        if (read == null) return string.Empty;
        try { return read.GetAwaiter().GetResult(); } catch { return string.Empty; }
    }
}
