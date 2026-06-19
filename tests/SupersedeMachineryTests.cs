using Cimian.CLI.Cimipkg.Services;
using WixToolset.Dtf.WindowsInstaller;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Contract tests for AB#3418 — cimipkg MSIs supersede older builds of the same
/// product so ARP never accumulates copies, and always re-lay their payload on a
/// re-install. This reverses #19 (NoUpgradeMachineryTests): the Upgrade table,
/// FindRelatedProducts, and RemoveExistingProducts are now REQUIRED, with
/// IgnoreRemoveFailure so a broken old package can never abort the new install.
/// A SetReinstallAll property action forces a full reinstall when the product is
/// already present so the payload always lands (no preflight.ps1-style toggle).
/// These tests fail loudly if any of that machinery is dropped again.
/// </summary>
public class SupersedeMachineryTests
{
    private static string BuildSchemaOnlyMsi()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"cimipkg-supersede-{Guid.NewGuid():N}.msi");
        using (var db = new Database(path, DatabaseOpenMode.Create))
        {
            MsiBuilder.CreateTables(db);
            db.Commit();
        }
        return path;
    }

    private static string BuildSchemaAndSequenceMsi(bool hasScripts, bool hasPayload)
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"cimipkg-supersede-{Guid.NewGuid():N}.msi");
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

    private static int SequenceOf(string msiPath, string action)
    {
        using var db = new Database(msiPath, DatabaseOpenMode.ReadOnly);
        using var view = db.OpenView(
            $"SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action`='{action}'");
        view.Execute();
        using var rec = view.Fetch();
        return rec is null ? -1 : rec.GetInteger(1);
    }

    [Fact]
    public void CreateTables_Creates_UpgradeTable()
    {
        var msi = BuildSchemaOnlyMsi();
        try
        {
            Assert.Contains("Upgrade", ListTables(msi));
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
    public void WriteInstallSequence_IncludesFindRelatedProducts(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            Assert.Contains("FindRelatedProducts", ListInstallExecuteSequenceActions(msi));
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
    public void WriteInstallSequence_IncludesRemoveExistingProducts(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            var actions = ListInstallExecuteSequenceActions(msi);
            Assert.Contains("RemoveExistingProducts", actions);
            // Must run after InstallInitialize and before ProcessComponents so old
            // builds are gone before the new payload is laid down.
            Assert.InRange(SequenceOf(msi, "RemoveExistingProducts"),
                SequenceOf(msi, "InstallInitialize") + 1,
                SequenceOf(msi, "ProcessComponents") - 1);
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Theory]
    [InlineData(true,  true)]
    [InlineData(false, false)]
    public void WriteInstallSequence_ForcesReinstall_BeforeCostFinalize(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            Assert.Contains("SetReinstallAll", ListInstallExecuteSequenceActions(msi));
            // REINSTALL must be set before CostFinalize for the component action
            // states to honor it; otherwise InstallFiles is skipped on a re-run.
            Assert.True(SequenceOf(msi, "SetReinstallAll") < SequenceOf(msi, "CostFinalize"));
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Fact]
    public void SetReinstallAll_IsAPropertyAction_ForcingReinstallAll()
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts: true, hasPayload: true);
        try
        {
            using var db = new Database(msi, DatabaseOpenMode.ReadOnly);
            using var view = db.OpenView(
                "SELECT `Type`, `Source`, `Target` FROM `CustomAction` WHERE `Action`='SetReinstallAll'");
            view.Execute();
            using var rec = view.Fetch();
            Assert.NotNull(rec);
            Assert.Equal(51, rec!.GetInteger(1)); // Type 51 = set property
            Assert.Equal("REINSTALL", rec.GetString(2));
            Assert.Equal("ALL", rec.GetString(3));
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Fact]
    public void WriteUpgradeTable_Row_IsUnboundedAndIgnoresRemoveFailure()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"cimipkg-supersede-{Guid.NewGuid():N}.msi");
        var upgradeCode = UpgradeCodeGenerator.GenerateUpgradeCode("ca.test.Sample");
        try
        {
            using (var db = new Database(path, DatabaseOpenMode.Create))
            {
                MsiBuilder.CreateTables(db);
                MsiBuilder.WriteUpgradeTable(db, upgradeCode);
                db.Commit();
            }

            using var rdb = new Database(path, DatabaseOpenMode.ReadOnly);
            using var view = rdb.OpenView(
                "SELECT `UpgradeCode`, `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty` FROM `Upgrade`");
            view.Execute();
            using var rec = view.Fetch();
            Assert.NotNull(rec);
            Assert.Equal($"{{{upgradeCode}}}".ToUpperInvariant(), rec!.GetString(1).ToUpperInvariant());
            Assert.Equal("0.0.0", rec.GetString(2));
            Assert.Equal("", rec.GetString(3)); // empty VersionMax = no upper bound
            // IgnoreRemoveFailure (4) must be set so a broken old package never aborts.
            Assert.Equal(4, rec.GetInteger(4) & 4);
            Assert.Equal("PREVIOUSVERSIONSINSTALLED", rec.GetString(5));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Theory]
    [InlineData(true,  true)]
    [InlineData(true,  false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public void Sequenced_AppSearch_AlwaysHasSignatureTable(bool hasScripts, bool hasPayload)
    {
        var msi = BuildSchemaAndSequenceMsi(hasScripts, hasPayload);
        try
        {
            var actions = ListInstallExecuteSequenceActions(msi);
            if (actions.Contains("AppSearch"))
            {
                Assert.Contains("Signature", ListTables(msi));
            }
        }
        finally
        {
            File.Delete(msi);
        }
    }

    [Fact]
    public void WriteInstallSequence_StillEmitsRequiredStandardActions()
    {
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
