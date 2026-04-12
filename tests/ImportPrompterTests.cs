using System;
using System.IO;
using System.Threading.Tasks;
using Cimian.CLI.Cimipkg.Services;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests for the publicly-testable surface of <see cref="ImportPrompter"/>:
/// <see cref="ImportPrompter.IsYes"/> parsing and <see cref="ImportPrompter.PromptYesNoAsync"/>
/// behavior under piped stdin (the fast path for CI).
///
/// The interactive branch of PromptYesNoAsync (real terminal input) and the
/// RunCimiimport shell-out are intentionally not covered here — they require
/// a real TTY and a cimiimport binary on disk, which xUnit runners don't
/// reliably provide. Those paths are verified manually during the
/// end-to-end run documented in the PR.
/// </summary>
public class ImportPrompterTests
{
    #region IsYes parsing

    [Theory]
    [InlineData("y", true)]
    [InlineData("Y", true)]
    [InlineData("yes", true)]
    [InlineData("YES", true)]
    [InlineData("Yes", true)]
    [InlineData("n", false)]
    [InlineData("N", false)]
    [InlineData("no", false)]
    [InlineData("NO", false)]
    [InlineData("", false)]
    [InlineData("maybe", false)]
    [InlineData("yeah", false)]        // strict — only y/yes
    [InlineData("true", false)]
    [InlineData("1", false)]
    public void IsYes_ReturnsExpected(string response, bool expected)
    {
        Assert.Equal(expected, ImportPrompter.IsYes(response));
    }

    #endregion

    #region PromptYesNoAsync under piped stdin

    [Fact]
    public async Task PromptYesNoAsync_PipedY_ReturnsTrue()
    {
        var result = await WithRedirectedStdin("y\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: false, TimeSpan.FromSeconds(5)));

        Assert.True(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_PipedYes_ReturnsTrue()
    {
        var result = await WithRedirectedStdin("yes\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: false, TimeSpan.FromSeconds(5)));

        Assert.True(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_PipedN_ReturnsFalse()
    {
        var result = await WithRedirectedStdin("n\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: true, TimeSpan.FromSeconds(5)));

        Assert.False(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_PipedEmptyLine_ReturnsDefaultYes()
    {
        var result = await WithRedirectedStdin("\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: true, TimeSpan.FromSeconds(5)));

        Assert.True(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_PipedEmptyLine_ReturnsDefaultNo()
    {
        var result = await WithRedirectedStdin("\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: false, TimeSpan.FromSeconds(5)));

        Assert.False(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_ResponseWithWhitespace_IsTrimmed()
    {
        var result = await WithRedirectedStdin("  y  \n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: false, TimeSpan.FromSeconds(5)));

        Assert.True(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_UnrecognizedInput_ReturnsFalse()
    {
        // Any non-empty response that isn't a yes-marker is treated as "no",
        // regardless of defaultYes. Matches MunkiPkg's Swift behavior at
        // munkipkg.swift:982: `return r == "y" || r == "yes"`.
        var result = await WithRedirectedStdin("maybe\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: false, TimeSpan.FromSeconds(5)));

        Assert.False(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_UnrecognizedInput_IgnoresDefaultYes()
    {
        // Explicit coverage for the "defaultYes is ignored for non-empty
        // non-yes input" semantics. If the user types anything other than
        // y/yes (even "true", "1", "ok"), we treat it as no — we don't fall
        // back to defaultYes. Only an empty response (Enter) uses defaultYes.
        var result = await WithRedirectedStdin("maybe\n", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: true, TimeSpan.FromSeconds(5)));

        Assert.False(result);
    }

    [Fact]
    public async Task PromptYesNoAsync_NoInput_TimesOutAndReturnsDefault()
    {
        // Empty stdin buffer — Console.ReadLine returns null immediately
        // (end-of-stream), which in our implementation is treated as "no
        // response → default". So this is effectively a regression test for
        // the null/empty path, not the timeout path. The timeout path
        // proper requires a real TTY.
        var result = await WithRedirectedStdin("", () =>
            ImportPrompter.PromptYesNoAsync("test?", defaultYes: true, TimeSpan.FromSeconds(5)));

        Assert.True(result);
    }

    #endregion

    /// <summary>
    /// Runs an action with stdin redirected from a StringReader. Ensures
    /// stdout is also captured so the prompt's "Prompt: " output doesn't
    /// pollute the xunit test output.
    /// </summary>
    private static async Task<T> WithRedirectedStdin<T>(string input, Func<Task<T>> action)
    {
        var originalIn = Console.In;
        var originalOut = Console.Out;
        try
        {
            Console.SetIn(new StringReader(input));
            Console.SetOut(TextWriter.Null);
            return await action();
        }
        finally
        {
            Console.SetIn(originalIn);
            Console.SetOut(originalOut);
        }
    }
}
