using System;
using System.IO;
using Cimian.CLI.Cimipkg.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests for PackageBuilder.LoadEnvironmentVariables placeholder-source resolution:
/// the .env file takes precedence and the process environment fills the rest, so
/// ${VAR} script placeholders resolve in CI where secrets arrive as env vars.
/// </summary>
public class PackageBuilderEnvTests
{
    private static PackageBuilder MakeBuilder()
    {
        var scriptProcessor = new ScriptProcessor(new Mock<ILogger<ScriptProcessor>>().Object);
        return new PackageBuilder(
            new Mock<ILogger<PackageBuilder>>().Object,
            scriptProcessor,
            new ChocolateyGenerator(new Mock<ILogger<ChocolateyGenerator>>().Object, scriptProcessor),
            new CodeSigner(new Mock<ILogger<CodeSigner>>().Object),
            new ZipArchiveHelper(new Mock<ILogger<ZipArchiveHelper>>().Object));
    }

    private static string MakeEmptyProjectDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cimipkg-envtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void LoadEnvironmentVariables_FallsBackToProcessEnvironment()
    {
        var name = "CIMIPKG_TEST_ENV_" + Guid.NewGuid().ToString("N");
        var dir = MakeEmptyProjectDir();
        Environment.SetEnvironmentVariable(name, "from-process");
        try
        {
            var vars = MakeBuilder().LoadEnvironmentVariables(dir, null);
            Assert.Equal("from-process", vars[name]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void LoadEnvironmentVariables_DotEnvTakesPrecedenceOverProcess()
    {
        var name = "CIMIPKG_TEST_ENV_" + Guid.NewGuid().ToString("N");
        var dir = MakeEmptyProjectDir();
        Environment.SetEnvironmentVariable(name, "from-process");
        try
        {
            File.WriteAllText(Path.Combine(dir, ".env"), $"{name}=from-dotenv\n");
            var vars = MakeBuilder().LoadEnvironmentVariables(dir, null);
            Assert.Equal("from-dotenv", vars[name]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
            Directory.Delete(dir, true);
        }
    }
}
