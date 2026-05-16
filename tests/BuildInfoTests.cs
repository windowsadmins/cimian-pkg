using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Cimian.CLI.Cimipkg.Models;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests for BuildInfo.DoSubstitutions and its private Expand helper.
/// Exercises placeholder resolution rules: built-in token precedence,
/// .env dictionary vs process environment, ${version} back-reference,
/// and fail-soft behavior for unresolved placeholders.
/// </summary>
public class BuildInfoTests
{
    private static BuildInfo MakeBuildInfo(
        string version = "1.0.0",
        string name = "TestPkg",
        string identifier = "com.test.pkg",
        string? description = null,
        string? signingCertificate = null,
        string? signingThumbprint = null,
        string? installLocation = null,
        string? installArguments = null,
        string? uninstallArguments = null,
        string? upgradeCode = null,
        string? keyPath = null)
    {
        return new BuildInfo
        {
            Product = new ProductInfo
            {
                Version = version,
                Name = name,
                Identifier = identifier,
                Description = description,
            },
            SigningCertificate = signingCertificate,
            SigningThumbprint = signingThumbprint,
            InstallLocation = installLocation,
            InstallArguments = installArguments,
            UninstallArguments = uninstallArguments,
            UpgradeCode = upgradeCode,
            KeyPath = keyPath,
        };
    }

    private static Dictionary<string, string> Env(params (string Key, string Value)[] entries)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in entries)
        {
            dict[key] = value;
        }
        return dict;
    }

    #region Built-in Token Tests

    [Fact]
    public void DoSubstitutions_Timestamp_ResolvesToExpectedFormat()
    {
        var bi = MakeBuildInfo(version: "${TIMESTAMP}");

        bi.DoSubstitutions();

        Assert.DoesNotContain("${TIMESTAMP}", bi.Product.Version);
        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}\.\d{4}$", bi.Product.Version);
    }

    [Fact]
    public void DoSubstitutions_Date_ResolvesToExpectedFormat()
    {
        var bi = MakeBuildInfo(version: "${DATE}");

        bi.DoSubstitutions();

        Assert.DoesNotContain("${DATE}", bi.Product.Version);
        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}$", bi.Product.Version);
    }

    [Fact]
    public void DoSubstitutions_DateTime_ResolvesToExpectedFormat()
    {
        var bi = MakeBuildInfo(version: "${DATETIME}");

        bi.DoSubstitutions();

        Assert.DoesNotContain("${DATETIME}", bi.Product.Version);
        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}\.\d{6}$", bi.Product.Version);
    }

    [Fact]
    public void DoSubstitutions_BuiltinToken_BeatsEnvDictionary()
    {
        // Even if the user shadows a built-in name in .env, the built-in wins.
        var bi = MakeBuildInfo(version: "${TIMESTAMP}");
        var envVars = Env(("TIMESTAMP", "shadowed-value"));

        bi.DoSubstitutions(envVars);

        Assert.DoesNotContain("shadowed-value", bi.Product.Version);
        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}\.\d{4}$", bi.Product.Version);
    }

    #endregion

    #region Env Dictionary Tests

    [Fact]
    public void DoSubstitutions_EnvDict_ResolvesUserPlaceholder()
    {
        var bi = MakeBuildInfo(signingThumbprint: "${SIGNING_CERT_THUMBPRINT}");
        var envVars = Env(("SIGNING_CERT_THUMBPRINT", "1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B"));

        bi.DoSubstitutions(envVars);

        Assert.Equal("1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B", bi.SigningThumbprint);
    }

    [Fact]
    public void DoSubstitutions_EnvDict_IsCaseInsensitive()
    {
        // The dict is built with OrdinalIgnoreCase, so lookup must work regardless
        // of the caller's casing conventions.
        var bi = MakeBuildInfo(signingCertificate: "${signing_cert_subject}");
        var envVars = Env(("SIGNING_CERT_SUBJECT", "EnterpriseCert"));

        bi.DoSubstitutions(envVars);

        Assert.Equal("EnterpriseCert", bi.SigningCertificate);
    }

    [Fact]
    public void DoSubstitutions_EnvDict_BeatsProcessEnvironment()
    {
        // Precedence: dict (from .env) wins over process env vars.
        const string varName = "CIMIPKG_TEST_PRECEDENCE_DICT_BEATS_ENV";
        var originalValue = Environment.GetEnvironmentVariable(varName);
        try
        {
            Environment.SetEnvironmentVariable(varName, "FROM_PROCESS_ENV");
            var bi = MakeBuildInfo(signingThumbprint: "${" + varName + "}");
            var envVars = Env((varName, "FROM_DICT"));

            bi.DoSubstitutions(envVars);

            Assert.Equal("FROM_DICT", bi.SigningThumbprint);
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, originalValue);
        }
    }

    #endregion

    #region Process Environment Tests

    [Fact]
    public void DoSubstitutions_ProcessEnv_ResolvesWhenDictMissing()
    {
        const string varName = "CIMIPKG_TEST_RESOLVES_FROM_PROCESS_ENV";
        var originalValue = Environment.GetEnvironmentVariable(varName);
        try
        {
            Environment.SetEnvironmentVariable(varName, "from-process");
            var bi = MakeBuildInfo(signingThumbprint: "${" + varName + "}");

            bi.DoSubstitutions();

            Assert.Equal("from-process", bi.SigningThumbprint);
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, originalValue);
        }
    }

    [Fact]
    public void DoSubstitutions_ProcessEnv_ResolvesWhenDictHasOtherKeys()
    {
        const string varName = "CIMIPKG_TEST_DICT_MISS_FALLS_TO_PROC_ENV";
        var originalValue = Environment.GetEnvironmentVariable(varName);
        try
        {
            Environment.SetEnvironmentVariable(varName, "from-process");
            var bi = MakeBuildInfo(signingThumbprint: "${" + varName + "}");
            var envVars = Env(("UNRELATED_VAR", "ignored"));

            bi.DoSubstitutions(envVars);

            Assert.Equal("from-process", bi.SigningThumbprint);
        }
        finally
        {
            Environment.SetEnvironmentVariable(varName, originalValue);
        }
    }

    #endregion

    #region Version Back-reference Tests

    [Fact]
    public void DoSubstitutions_VersionBackRef_ResolvesInName()
    {
        var bi = MakeBuildInfo(version: "1.2.3", name: "Pkg-${version}");

        bi.DoSubstitutions();

        Assert.Equal("Pkg-1.2.3", bi.Product.Name);
    }

    [Fact]
    public void DoSubstitutions_VersionBackRef_ResolvesInIdentifier()
    {
        var bi = MakeBuildInfo(version: "1.2.3", identifier: "com.test.pkg.${version}");

        bi.DoSubstitutions();

        Assert.Equal("com.test.pkg.1.2.3", bi.Product.Identifier);
    }

    [Fact]
    public void DoSubstitutions_VersionBackRef_UsesResolvedVersion()
    {
        // When version itself is a built-in token, the back-reference in other
        // fields must see the substituted value, not the placeholder.
        var bi = MakeBuildInfo(version: "${DATE}", name: "Pkg-${version}");

        bi.DoSubstitutions();

        Assert.DoesNotContain("${", bi.Product.Name);
        Assert.Matches(@"^Pkg-\d{4}\.\d{2}\.\d{2}$", bi.Product.Name);
    }

    [Fact]
    public void DoSubstitutions_VersionBackRef_LiteralInVersionField()
    {
        // ${version} inside Product.Version itself has no prior value to
        // substitute, so it stays literal rather than recursing.
        var bi = MakeBuildInfo(version: "${version}");

        bi.DoSubstitutions();

        Assert.Equal("${version}", bi.Product.Version);
    }

    #endregion

    #region Fail-soft Tests

    [Fact]
    public void DoSubstitutions_UnresolvedPlaceholder_StaysLiteral()
    {
        var bi = MakeBuildInfo(signingThumbprint: "${COMPLETELY_UNKNOWN_TOKEN_NAME}");

        bi.DoSubstitutions();

        Assert.Equal("${COMPLETELY_UNKNOWN_TOKEN_NAME}", bi.SigningThumbprint);
    }

    [Fact]
    public void DoSubstitutions_UnresolvedPlaceholder_DoesNotThrow()
    {
        var bi = MakeBuildInfo(signingThumbprint: "${MISSING}");

        // Must not throw; downstream (signtool) will surface the real error.
        var ex = Record.Exception(() => bi.DoSubstitutions());

        Assert.Null(ex);
    }

    [Fact]
    public void DoSubstitutions_NullField_StaysNull()
    {
        var bi = MakeBuildInfo();
        Assert.Null(bi.SigningCertificate);

        bi.DoSubstitutions();

        Assert.Null(bi.SigningCertificate);
    }

    [Fact]
    public void DoSubstitutions_EmptyField_StaysEmpty()
    {
        var bi = MakeBuildInfo(signingThumbprint: "");

        bi.DoSubstitutions();

        Assert.Equal("", bi.SigningThumbprint);
    }

    #endregion

    #region Mixed Token Tests

    [Fact]
    public void DoSubstitutions_MixedBuiltinAndEnv_InSingleField()
    {
        var bi = MakeBuildInfo(version: "${DATE}.${BUILD_NUMBER}");
        var envVars = Env(("BUILD_NUMBER", "42"));

        bi.DoSubstitutions(envVars);

        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}\.42$", bi.Product.Version);
    }

    [Fact]
    public void DoSubstitutions_MultipleTokens_AllResolve()
    {
        var bi = MakeBuildInfo(
            version: "1.0.0",
            name: "${TIMESTAMP}-${version}",
            description: "Built on ${DATE} from commit ${GIT_SHA}");
        var envVars = Env(("GIT_SHA", "abc123"));

        bi.DoSubstitutions(envVars);

        Assert.Matches(@"^\d{4}\.\d{2}\.\d{2}\.\d{4}-1\.0\.0$", bi.Product.Name);
        Assert.Matches(@"^Built on \d{4}\.\d{2}\.\d{2} from commit abc123$", bi.Product.Description!);
    }

    [Fact]
    public void DoSubstitutions_LiteralValue_PassesThroughUnchanged()
    {
        // Fast path: strings with no ${ marker should not be touched.
        var bi = MakeBuildInfo(
            signingThumbprint: "1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B",
            signingCertificate: "EnterpriseCert");

        bi.DoSubstitutions();

        Assert.Equal("1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B", bi.SigningThumbprint);
        Assert.Equal("EnterpriseCert", bi.SigningCertificate);
    }

    #endregion

    #region New Field Coverage Tests

    [Fact]
    public void DoSubstitutions_InstallLocation_ResolvesPlaceholder()
    {
        var bi = MakeBuildInfo(installLocation: @"C:\Program Files\${APP_NAME}");
        var envVars = Env(("APP_NAME", "MyApp"));

        bi.DoSubstitutions(envVars);

        Assert.Equal(@"C:\Program Files\MyApp", bi.InstallLocation);
    }

    [Fact]
    public void DoSubstitutions_InstallArguments_ResolvesPlaceholder()
    {
        var bi = MakeBuildInfo(installArguments: "/quiet /log ${LOG_PATH}");
        var envVars = Env(("LOG_PATH", @"C:\Temp\install.log"));

        bi.DoSubstitutions(envVars);

        Assert.Equal(@"/quiet /log C:\Temp\install.log", bi.InstallArguments);
    }

    [Fact]
    public void DoSubstitutions_UninstallArguments_ResolvesPlaceholder()
    {
        var bi = MakeBuildInfo(uninstallArguments: "/quiet /norestart ${EXTRA}");
        var envVars = Env(("EXTRA", "/log=off"));

        bi.DoSubstitutions(envVars);

        Assert.Equal("/quiet /norestart /log=off", bi.UninstallArguments);
    }

    [Fact]
    public void DoSubstitutions_UpgradeCode_ResolvesPlaceholder()
    {
        const string guid = "12345678-1234-1234-1234-123456789012";
        var bi = MakeBuildInfo(upgradeCode: "${APP_UPGRADE_CODE}");
        var envVars = Env(("APP_UPGRADE_CODE", guid));

        bi.DoSubstitutions(envVars);

        Assert.Equal(guid, bi.UpgradeCode);
    }

    [Fact]
    public void DoSubstitutions_SigningCertificate_ResolvesPlaceholder()
    {
        var bi = MakeBuildInfo(signingCertificate: "${SIGNING_CERT_SUBJECT}");
        var envVars = Env(("SIGNING_CERT_SUBJECT", "EnterpriseCert"));

        bi.DoSubstitutions(envVars);

        Assert.Equal("EnterpriseCert", bi.SigningCertificate);
    }

    [Fact]
    public void DoSubstitutions_SigningThumbprint_ResolvesPlaceholder()
    {
        var bi = MakeBuildInfo(signingThumbprint: "${SIGNING_CERT_THUMBPRINT}");
        var envVars = Env(("SIGNING_CERT_THUMBPRINT", "1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B"));

        bi.DoSubstitutions(envVars);

        Assert.Equal("1423F241DFF85AD2C8F31DBD70FB597DAC85BA4B", bi.SigningThumbprint);
    }

    [Fact]
    public void DoSubstitutions_KeyPath_ResolvesEnvPlaceholder()
    {
        var bi = MakeBuildInfo(keyPath: @"${BIN_DIR}\foo.exe");
        var envVars = Env(("BIN_DIR", "bin"));

        bi.DoSubstitutions(envVars);

        Assert.Equal(@"bin\foo.exe", bi.KeyPath);
    }

    [Fact]
    public void DoSubstitutions_KeyPath_ResolvesVersionBackReference()
    {
        // ${version} expands to the resolved product version, same back-reference
        // behaviour as the other path-like fields. Lets users pin key_path to a
        // versioned subdir without restating the version literal.
        var bi = MakeBuildInfo(version: "2026.05.16.1530", keyPath: @"v${version}\app.exe");

        bi.DoSubstitutions();

        Assert.Equal(@"v2026.05.16.1530\app.exe", bi.KeyPath);
    }

    [Fact]
    public void DoSubstitutions_KeyPath_NullStaysNull()
    {
        // KeyPath is optional; substitution must be a no-op when not set so
        // a YAML without a `key_path:` field stays clean (no empty string
        // bleeding into downstream consumers).
        var bi = MakeBuildInfo(keyPath: null);

        bi.DoSubstitutions();

        Assert.Null(bi.KeyPath);
    }

    #endregion
}
