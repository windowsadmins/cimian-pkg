using Cimian.CLI.Cimipkg.Services;
using WixToolset.Dtf.WindowsInstaller;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Regression tests for #19 — cimipkg MSIs do not participate in Windows
/// Installer major upgrades. The whole point of the change is that generated
/// MSIs are stateless deployers: each install just runs preinstall, copies
/// payload, runs postinstall, regardless of what's already on disk. If the
/// Upgrade table or FindRelatedProducts / RemoveExistingProducts ever sneak
/// back in (by accident or as a "helpful" addition during a refactor),
/// upgrades start failing silently again because Windows Installer goes
/// hunting for the previous MSI's source file. These tests fail loudly
/// before that ships.
/// </summary>
public class NoUpgradeMachineryTests
{
    /// <summary>
    /// Build a fresh MSI database in a temp file, run only the schema-creation
    /// stage of the builder, and return the path. Cleanup is the caller's job.
    /// </summary>
    private static string BuildSchemaOnlyMsi()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"cimipkg-noupgrade-{Guid.NewGuid():N}.msi");
        using (var db = new Database(path, DatabaseOpenMode.Create))
        {
            MsiBuilder.CreateTables(db);
            db.Commit();
        }
        return path;
    }

    /// <summary>
    /// Same as BuildSchemaOnlyMsi but also populates InstallExecuteSequence
    /// with the standard cimipkg install sequence. Caller picks whether scripts
    /// and payload are present so all branches of WriteInstallSequence get
    /// exercised.
    /// </summary>
    private static string BuildSchemaAndSequenceMsi(bool hasScripts, bool hasPayload)
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"cimipkg-noupgrade-{Guid.NewGuid():N}.msi");
        using (var db = new Database(path, DatabaseOpenMode.Create))
        {
            MsiBuilder.CreateTables(db);
            MsiBuilder.WriteInstallSequence(db, hasScripts, hasPayload);
            db.Commit();
        }
        return path;
    }

    private static List<string> ListTables(string msiPath)
    {
        using var db = new Database(msiPath, DatabaseOpenMode.ReadOnly);
        // _Tables is the MSI metadata view that lists every user table.
        using var view = db.OpenView("SELECT `Name` FROM `_Tables`");
        view.Execute();
        var names = new List<string>();
        for (var rec = view.Fetch(); rec != null; rec = view.Fetch())
        {
            using (rec) names.Add(rec.GetString(1));
        }
        return names;
    }

    private static List<string> ListInstallExecuteSequenceActions(string msiPath)
    {
        using var db = new Database(msiPath, DatabaseOpenMode.ReadOnly);
        using var view = db.OpenView("SELECT `Action` FROM `InstallExecuteSequence`");
        view.Execute();
        var actions = new List<string>();
        for (var rec = view.Fetch(); rec != null; rec = view.Fetch())
        {
            using (rec) actions.Add(rec.GetString(1));
        }
        return actions;
    }

    [Fact]
    public void CreateTables_DoesNotCreate_UpgradeTable()
    {
        var msi = BuildSchemaOnlyMsi();
        try
        {
            var tables = ListTables(msi);
            Assert.DoesNotContain("Upgrade", tables);
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Theory]
    [InlineData(true,  true)]
    [InlineData(true,  false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void WriteInstallSequence_OmitsFindRelatedProducts(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            var actions = ListInstallExecuteSequenceActions(msi);
            Assert.DoesNotContain("FindRelatedProducts", actions);
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Theory]
    [InlineData(true,  true)]
    [InlineData(true,  false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void WriteInstallSequence_OmitsRemoveExistingProducts(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            var actions = ListInstallExecuteSequenceActions(msi);
            Assert.DoesNotContain("RemoveExistingProducts", actions);
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Fact]
    public void WriteInstallSequence_StillEmitsRequiredStandardActions()
    {
        // Sanity guard: removing upgrade machinery must not have stripped the
        // actions a stateless deployer still needs to actually install files
        // and finalize the install.
        var msi = BuildSchemaAndSequenceMsi(hasScripts: true, hasPayload: true);
        try
        {
            var actions = ListInstallExecuteSequenceActions(msi);
            Assert.Contains("LaunchConditions", actions);
            Assert.Contains("CostInitialize", actions);
            Assert.Contains("InstallInitialize", actions);
            Assert.Contains("InstallFiles", actions);
            Assert.Contains("InstallFinalize", actions);
            Assert.Contains("CimianPreinstall", actions);
            Assert.Contains("CimianPostinstall", actions);
        }
        finally
        {
            File.Delete(msi);
        }
    }
}
