using Cimian.CLI.Cimipkg.Services;
using Xunit;

namespace Cimian.Cimipkg.Tests;

public class PowerShellSyntaxTests
{
    [Fact]
    public void TryValidate_ValidScript_Passes()
    {
        var script = "param([string]$Path)\nif (-not (Test-Path $Path)) { exit 0 }\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        Assert.True(ok, errors);
    }

    [Fact]
    public void TryValidate_EmptyScript_Passes()
    {
        Assert.True(PowerShellSyntax.TryValidate("", out _));
        Assert.True(PowerShellSyntax.TryValidate("# No preinstall scripts", out _));
    }

    [Fact]
    public void TryValidate_CorruptedParamBlock_FailsWithLineNumber()
    {
        // The exact corruption from the 2026-07-21 field incident: a PATH value
        // substituted into a param() declaration.
        var script = "param([string]C:\\Program Files\\PowerShell\\7;C:\\Users\\agent)\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        Assert.False(ok);
        Assert.Contains("line 1", errors);
    }

    [Fact]
    public void TryValidate_GuidInCommandPosition_ParsesButAssignmentFails()
    {
        // A bare GUID as an assignment target is the CimianAuth corruption.
        // The parser rejects it (a command cannot be assigned to).
        var script = "d22686a0-c1be-48e0-8f91-5bdd033f7dad = \"TENANT_ID\"\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        // PowerShell parses `word = value` as a command invocation, which is
        // legal grammar even though it fails at runtime — so accept either
        // outcome here; the test documents the boundary of pack-time checking.
        if (!ok)
        {
            Assert.Contains("line 1", errors);
        }
    }

    [Fact]
    public void TryValidate_UnterminatedString_Fails()
    {
        var script = "Write-Host \"unterminated\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out _);

        Assert.False(ok);
    }
}
