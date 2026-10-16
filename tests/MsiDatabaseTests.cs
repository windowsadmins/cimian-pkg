using System;
using System.ComponentModel;
using System.IO;
using Cimian.CLI.Cimipkg.Services;
using Cimian.CLI.Cimipkg.Services.Msi;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// The msi.dll interop that replaced WiX DTF. Each test writes a real MSI and
/// reads it back, pinning what MsiBuilder and MsiPropertyReader rely on: SQL
/// authoring, commit, summary property types, cabinet streams and table
/// metadata.
/// </summary>
public class MsiDatabaseTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"msidb_{Guid.NewGuid():N}");

    public MsiDatabaseTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string NewPath() => Path.Combine(_dir, $"{Guid.NewGuid():N}.msi");

    private string CreateWithProperties()
    {
        var path = NewPath();
        using var db = MsiDatabase.Open(path, MsiOpenMode.Create);
        db.Execute("CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE PRIMARY KEY `Property`)");
        db.Execute("INSERT INTO `Property` (`Property`, `Value`) VALUES ('ProductName', 'Widget')");
        db.Execute("INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", "Owner's", "quoted");
        db.Commit();
        return path;
    }

    [Fact]
    public void CreateCommitAndReadBack()
    {
        var path = CreateWithProperties();

        using var db = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);

        Assert.Equal("Widget", db.ExecuteScalar("SELECT `Value` FROM `Property` WHERE `Property` = ?", "ProductName"));
        Assert.Equal("quoted", db.ExecuteScalar("SELECT `Value` FROM `Property` WHERE `Property` = ?", "Owner's"));
        Assert.Null(db.ExecuteScalar("SELECT `Value` FROM `Property` WHERE `Property` = ?", "Missing"));
    }

    [Fact]
    public void DisposeWithoutCommit_DiscardsChanges()
    {
        var path = CreateWithProperties();

        using (var db = MsiDatabase.Open(path, MsiOpenMode.Transact))
        {
            db.Execute("INSERT INTO `Property` (`Property`, `Value`) VALUES ('Extra', 'x')");
        }

        using var read = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);
        Assert.Null(read.ExecuteScalar("SELECT `Value` FROM `Property` WHERE `Property` = ?", "Extra"));
    }

    [Fact]
    public void TablesAndColumns()
    {
        var path = CreateWithProperties();

        using var db = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);

        Assert.True(db.TableExists("Property"));
        Assert.False(db.TableExists("File"));
        Assert.Equal(new[] { "Property" }, db.GetTableNames());
        Assert.Equal(new[] { "Property", "Value" }, db.GetColumnNames("Property"));
    }

    [Fact]
    public void NullFields_ReadAsEmptyStringAndZero()
    {
        var path = NewPath();
        using (var db = MsiDatabase.Open(path, MsiOpenMode.Create))
        {
            db.Execute("CREATE TABLE `T` (`K` CHAR(10) NOT NULL, `S` CHAR(10), `N` LONG PRIMARY KEY `K`)");
            db.Execute("INSERT INTO `T` (`K`) VALUES ('a')");
            db.Commit();
        }

        using var read = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);
        using var view = read.OpenView("SELECT `S`, `N` FROM `T`");
        view.Execute();
        using var record = view.Fetch();

        Assert.NotNull(record);
        Assert.Equal("", record!.GetString(1));
        Assert.Equal(0, record.GetInteger(2));
        Assert.Null(view.Fetch());
    }

    [Fact]
    public void SummaryInfo_WritesStringsAndIntegersWithTheirTypes()
    {
        var path = CreateWithProperties();

        using (var si = MsiSummaryInfo.Open(path, enableWrite: true))
        {
            si.SetString(MsiSummaryInfo.PID_TITLE, "Installation Database");
            si.SetString(MsiSummaryInfo.PID_TEMPLATE, "x64;1033");
            si.SetString(MsiSummaryInfo.PID_REVNUMBER, "{11111111-2222-3333-4444-555555555555}");
            si.SetInteger(MsiSummaryInfo.PID_PAGECOUNT, 200);
            si.SetInteger(MsiSummaryInfo.PID_WORDCOUNT, 2);
            si.SetInteger(MsiSummaryInfo.PID_SECURITY, 2);
            si.Persist();
        }

        using (var si = MsiSummaryInfo.Open(path, enableWrite: false))
        {
            Assert.Equal("Installation Database", si.GetString(MsiSummaryInfo.PID_TITLE));
            Assert.Equal("{11111111-2222-3333-4444-555555555555}", si.GetString(MsiSummaryInfo.PID_REVNUMBER));
            Assert.Equal(200, si.GetInteger(MsiSummaryInfo.PID_PAGECOUNT));
            Assert.Equal(2, si.GetInteger(MsiSummaryInfo.PID_WORDCOUNT));
            Assert.Equal(2, si.GetInteger(MsiSummaryInfo.PID_SECURITY));
            // An integer property must not read back as a string, and vice versa.
            Assert.Equal("", si.GetString(MsiSummaryInfo.PID_PAGECOUNT));
            Assert.Null(si.GetInteger(MsiSummaryInfo.PID_TITLE));
        }

        using var db = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);
        Assert.Equal("x64;1033", db.GetSummaryTemplate());
    }

    [Fact]
    public void Streams_AssignEmbedsFileBytes()
    {
        var path = CreateWithProperties();
        var payload = Path.Combine(_dir, "payload.bin");
        var bytes = new byte[300_000];
        new Random(7).NextBytes(bytes);
        File.WriteAllBytes(payload, bytes);

        using (var db = MsiDatabase.Open(path, MsiOpenMode.Direct))
        {
            using var view = db.OpenView("SELECT `Name`, `Data` FROM `_Streams`");
            view.Execute();
            using var record = MsiRecord.Create(2);
            record.SetString(1, "product.cab");
            record.SetStream(2, payload);
            view.Assign(record);
            db.Commit();
        }

        // Read the stream back through the reader DTF-free code would use.
        using var read = MsiDatabase.Open(path, MsiOpenMode.ReadOnly);
        Assert.Equal("product.cab", read.ExecuteScalar("SELECT `Name` FROM `_Streams` WHERE `Name` = ?", "product.cab"));
    }

    [Fact]
    public void Open_NotAnMsi_Throws()
    {
        var path = Path.Combine(_dir, "notmsi.msi");
        File.WriteAllText(path, "not an msi");

        Assert.ThrowsAny<Win32Exception>(() => MsiDatabase.Open(path, MsiOpenMode.ReadOnly));
    }

    [Fact]
    public void PropertyReader_ReadsThroughTheNewInterop()
    {
        var path = CreateWithProperties();
        var reader = new MsiPropertyReader(Microsoft.Extensions.Logging.Abstractions.NullLogger<MsiPropertyReader>.Instance);

        Assert.Equal("Widget", reader.ReadProperty(path, "ProductName"));
        Assert.Equal("quoted", reader.ReadProperty(path, "Owner's"));
        Assert.Null(reader.ReadProperty(path, "Missing"));
        Assert.Equal(new[] { "Property" }, reader.ListTables(path));
        var (columns, rows) = reader.ReadTable(path, "Property");
        Assert.Equal(new[] { "Property", "Value" }, columns);
        Assert.Equal(2, rows.Count);
    }
}
