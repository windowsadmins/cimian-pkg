using System;
using System.Collections.Generic;
using System.Reflection;
using Cimian.CLI.Cimipkg.Services;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Guards the shape of the self-update lock release that cimipkg injects into the
/// preinstall of every package shipping an executable.
///
/// The regression these cover is a hang, not a failure, which is why they assert on
/// the generated text rather than on behaviour. Get-ScheduledTask can block forever
/// on a host whose Task Scheduler enumeration has wedged: the service still reports
/// Running, nothing throws, and neither try/catch nor -ErrorAction makes any
/// difference. Because this block is injected into every such package, an unbounded
/// call means one wedged Task Scheduler silently stops ALL software installing on
/// that machine for as long as it stays up.
/// </summary>
public class SelfUpdateLockReleaseTests
{
    private static string Generate(params string[] exeNames)
    {
        var method = typeof(MsiBuilder).GetMethod(
            "BuildSelfUpdateLockRelease",
            BindingFlags.NonPublic | BindingFlags.Static);

        Assert.True(method != null,
            "BuildSelfUpdateLockRelease is what these tests exist to guard; if it was " +
            "renamed, update the tests rather than deleting them");

        return (string)method!.Invoke(null, new object[] { (IReadOnlyList<string>)exeNames })!;
    }

    [Fact]
    public void ScheduledTaskScan_HasADeadline()
    {
        var script = Generate("Example.exe");

        Assert.Contains("cimianTaskScanTimeoutMs", script);

        // Declaring a timeout without waiting on it leaves the call unbounded.
        Assert.Contains("WaitOne(", script);
    }

    [Fact]
    public void ScheduledTaskScan_RunsOffTheInstallThread()
    {
        // The scan has to be abandonable, which means it cannot run inline: a
        // runspace can be walked away from, a pipeline on this thread cannot.
        Assert.Contains("[PowerShell]::Create()", Generate("Example.exe"));
    }

    [Fact]
    public void ProcessStop_ComesAfterTheBoundedScan()
    {
        var script = Generate("Example.exe");

        // Stopping the processes is the part that actually releases the file locks
        // the install needs. It sits after the task scan, so the scan's timeout is
        // what guarantees it is still reached on a host where Task Scheduler will
        // not answer.
        var scanIndex = script.IndexOf("cimianTaskScanTimeoutMs", StringComparison.Ordinal);
        var stopIndex = script.IndexOf("Stop-Process", StringComparison.Ordinal);

        Assert.True(scanIndex >= 0, "the bounded scan should be present");
        Assert.True(stopIndex > scanIndex, "the process stop should follow the bounded scan");
    }

    [Fact]
    public void PayloadExeNames_AreBakedIn()
    {
        var script = Generate("Alpha.exe", "Beta.exe");

        Assert.Contains("'Alpha.exe'", script);
        Assert.Contains("'Beta.exe'", script);
    }

    [Fact]
    public void PayloadExeNames_WithQuotes_AreEscaped()
    {
        // A single quote in a payload name would otherwise close the PowerShell
        // string literal and produce a script that does not parse.
        Assert.Contains("'Odd''Name.exe'", Generate("Odd'Name.exe"));
    }
}
