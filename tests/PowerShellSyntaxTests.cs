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
    public void TryValidate_GuidInCommandPosition_Fails()
    {
        // A bare GUID as an assignment target is the CimianAuth corruption.
        // PowerShell parses `word = value` as a command invocation, so the
        // parser accepts it; the AST check rejects it because no command of
        // that name exists.
        var script = "d22686a0-c1be-48e0-8f91-5bdd033f7dad = \"TENANT_ID\"\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        Assert.False(ok);
        Assert.Contains("line 1", errors);
    }

    [Theory]
    [InlineData("x64 = 'C:\\Program Files'\nexit 0", 1)]
    [InlineData("x64 = \"C:\\Program Files\"\nexit 0", 1)]
    [InlineData("x64 += 'more'\nexit 0", 1)]
    [InlineData("x64= 'tight'\nexit 0", 1)]
    [InlineData("x64='C:\\Program Files'\nexit 0", 1)]
    [InlineData("x64=$env:ProgramFiles\nexit 0", 1)]
    [InlineData("x64 =$env:ProgramFiles\nexit 0", 1)]
    [InlineData("x64 -= 1\nexit 0", 1)]
    [InlineData("exit 0\n", 0)]
    [InlineData("if ($true) {\n    x64 = 'nested'\n}\nexit 0", 2)]
    public void TryValidate_AssignmentMissingDollar_FailsWithLineNumber(string script, int line)
    {
        // The `${x64}` placeholder-substitution case: the substitution
        // consumed `$x64` and left `x64 = ...`, which parses as a call to a
        // command named x64 and only fails on the device.
        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        if (line == 0)
        {
            Assert.True(ok, errors);
            return;
        }

        Assert.False(ok);
        Assert.Contains($"line {line}", errors);
        Assert.Contains("'x64'", errors);
    }

    [Theory]
    [InlineData("$x64 = 'C:\\Program Files'\nexit 0")]
    [InlineData("${x64} = 'braced'\nexit 0")]
    [InlineData("Write-Output \"=\" 'quoted equals is an argument'")]
    [InlineData("Write-Output = 'a real command'")]
    [InlineData("function x64 { param($a, $b) }\nx64 = 'script-defined'")]
    [InlineData("$h = @{ Arch = 'x64' }\n$h.Arch = 'arm64'")]
    [InlineData("$list = @(1, 2)\n$list[0] = 3")]
    public void TryValidate_LegitimateEqualsUsage_Passes(string script)
    {
        var ok = PowerShellSyntax.TryValidate(script, out var errors);

        Assert.True(ok, errors);
    }

    [Fact]
    public void TryValidate_UnterminatedString_Fails()
    {
        var script = "Write-Host \"unterminated\nexit 0";

        var ok = PowerShellSyntax.TryValidate(script, out _);

        Assert.False(ok);
    }
}
