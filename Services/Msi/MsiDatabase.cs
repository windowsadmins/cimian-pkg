using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Cimian.CLI.Cimipkg.Services.Msi;

/// <summary>How <see cref="MsiDatabase.Open"/> opens a database (the MSIDBOPEN_* persist modes).</summary>
public enum MsiOpenMode
{
    ReadOnly = 0,
    Transact = 1,
    Direct = 2,
    Create = 3,
}

/// <summary>
/// An MSI database, over msi.dll directly.
///
/// cimipkg authors MSIs entirely through SQL -- CREATE TABLE and INSERT -- plus
/// two things SQL cannot express: embedding cabinet streams in <c>_Streams</c>
/// and writing the Summary Information stream (<see cref="MsiSummaryInfo"/>).
/// Reading back is SELECT, row fetch and table metadata. Values go into a query
/// as <c>?</c> parameters bound from a record, never spliced into the SQL.
/// Nothing is written until <see cref="Commit"/>; disposing without it discards
/// a created or transacted database.
/// </summary>
public sealed class MsiDatabase : IDisposable
{
    private readonly MsiHandle _handle;

    private MsiDatabase(MsiHandle handle) => _handle = handle;

    internal MsiHandle Handle => _handle;

    /// <summary>Opens or creates <paramref name="path"/>. Throws <see cref="Win32Exception"/> on failure.</summary>
    public static MsiDatabase Open(string path, MsiOpenMode mode)
    {
        MsiNative.Check(MsiNative.MsiOpenDatabaseW(path, (IntPtr)(int)mode, out var handle));
        return new MsiDatabase(handle);
    }

    /// <summary>Runs a statement that returns no rows (CREATE, INSERT, UPDATE, DELETE).</summary>
    public void Execute(string sql, params string[] parameters)
    {
        using var view = OpenView(sql);
        view.Execute(parameters);
    }

    /// <summary>Prepares a query. Call <see cref="MsiView.Execute"/> before fetching.</summary>
    public MsiView OpenView(string sql)
    {
        MsiNative.Check(MsiNative.MsiDatabaseOpenViewW(_handle, sql, out var view));
        return new MsiView(view);
    }

    /// <summary>The first column of the first row the query returns, or null when it returns no rows.</summary>
    public string? ExecuteScalar(string sql, params string[] parameters)
    {
        using var view = OpenView(sql);
        view.Execute(parameters);
        using var record = view.Fetch();
        return record?.GetString(1);
    }

    /// <summary>True when the database has a table named <paramref name="table"/>.</summary>
    public bool TableExists(string table)
    {
        var state = MsiNative.MsiDatabaseIsTablePersistentW(_handle, table);
        if (state == MsiNative.MSICONDITION_ERROR)
        {
            throw new Win32Exception($"Could not check MSI table '{table}'");
        }
        return state != MsiNative.MSICONDITION_NONE;
    }

    /// <summary>The names of the database's persistent tables, in catalog order.</summary>
    public List<string> GetTableNames()
    {
        var names = new List<string>();
        using var view = OpenView("SELECT `Name` FROM `_Tables`");
        view.Execute();
        for (var record = view.Fetch(); record != null; record = view.Fetch())
        {
            using (record)
            {
                names.Add(record.GetString(1));
            }
        }
        return names;
    }

    /// <summary>The column names of <paramref name="table"/>, in column order.</summary>
    public List<string> GetColumnNames(string table)
    {
        using var view = OpenView($"SELECT * FROM `{table}`");
        MsiNative.Check(MsiNative.MsiViewGetColumnInfo(view.Handle, MsiNative.MSICOLINFO_NAMES, out var info));
        using var record = new MsiRecord(info);
        var names = new List<string>();
        for (var i = 1; i <= record.FieldCount; i++)
        {
            names.Add(record.GetString(i));
        }
        return names;
    }

    /// <summary>The Summary Information Template ("Platform;LanguageID"), or "" when it is not set.</summary>
    public string GetSummaryTemplate()
    {
        MsiNative.Check(MsiNative.MsiGetSummaryInformationW(_handle, null, 0, out var handle));
        using var summary = new MsiSummaryInfo(handle);
        return summary.GetString(MsiSummaryInfo.PID_TEMPLATE);
    }

    /// <summary>Writes every change made since the database was opened.</summary>
    public void Commit() => MsiNative.Check(MsiNative.MsiDatabaseCommit(_handle));

    public void Dispose() => _handle.Dispose();
}

/// <summary>A query over an <see cref="MsiDatabase"/>.</summary>
public sealed class MsiView : IDisposable
{
    private readonly MsiHandle _handle;

    internal MsiView(MsiHandle handle) => _handle = handle;

    internal MsiHandle Handle => _handle;

    /// <summary>Runs the query. Each of <paramref name="parameters"/> binds, in order, to a <c>?</c> marker.</summary>
    public void Execute(params string[] parameters)
    {
        if (parameters.Length == 0)
        {
            MsiNative.Check(MsiNative.MsiViewExecute(_handle, IntPtr.Zero));
            return;
        }

        using var record = MsiRecord.Create(parameters.Length);
        for (var i = 0; i < parameters.Length; i++)
        {
            record.SetString(i + 1, parameters[i]);
        }
        MsiNative.Check(MsiNative.MsiViewExecute(_handle, record.Handle.DangerousGetHandle()));
    }

    /// <summary>The next row, or null once every row has been read.</summary>
    public MsiRecord? Fetch()
    {
        var result = MsiNative.MsiViewFetch(_handle, out var record);
        if (result == MsiNative.ERROR_NO_MORE_ITEMS)
        {
            record.Dispose();
            return null;
        }
        MsiNative.Check(result);
        return new MsiRecord(record);
    }

    /// <summary>Inserts <paramref name="record"/>, or replaces the row with the same primary key.</summary>
    public void Assign(MsiRecord record) =>
        MsiNative.Check(MsiNative.MsiViewModify(_handle, MsiNative.MSIMODIFY_ASSIGN, record.Handle));

    public void Dispose()
    {
        MsiNative.MsiViewClose(_handle);
        _handle.Dispose();
    }
}

/// <summary>A row of fields, numbered from 1.</summary>
public sealed class MsiRecord : IDisposable
{
    private readonly MsiHandle _handle;

    internal MsiRecord(MsiHandle handle) => _handle = handle;

    internal MsiHandle Handle => _handle;

    /// <summary>A new, empty record with <paramref name="fieldCount"/> fields.</summary>
    public static MsiRecord Create(int fieldCount)
    {
        var handle = MsiNative.MsiCreateRecord((uint)fieldCount);
        if (handle.IsInvalid)
        {
            throw new Win32Exception("Could not create an MSI record");
        }
        return new MsiRecord(handle);
    }

    public int FieldCount => (int)MsiNative.MsiRecordGetFieldCount(_handle);

    public void SetString(int field, string value) =>
        MsiNative.Check(MsiNative.MsiRecordSetStringW(_handle, (uint)field, value));

    /// <summary>Loads the file at <paramref name="path"/> into a stream field.</summary>
    public void SetStream(int field, string path) =>
        MsiNative.Check(MsiNative.MsiRecordSetStreamW(_handle, (uint)field, path));

    /// <summary>The field as a string; a null field reads as the empty string.</summary>
    public string GetString(int field)
    {
        uint length = 256;
        var buffer = new StringBuilder((int)length);
        var result = MsiNative.MsiRecordGetStringW(_handle, (uint)field, buffer, ref length);
        if (result == MsiNative.ERROR_MORE_DATA)
        {
            // length now holds the size without the terminator.
            length++;
            buffer = new StringBuilder((int)length);
            result = MsiNative.MsiRecordGetStringW(_handle, (uint)field, buffer, ref length);
        }
        MsiNative.Check(result);
        return buffer.ToString();
    }

    /// <summary>The field as an integer; a null field reads as 0.</summary>
    public int GetInteger(int field)
    {
        var value = MsiNative.MsiRecordGetInteger(_handle, (uint)field);
        return value == MsiNative.MSI_NULL_INTEGER ? 0 : value;
    }

    public void Dispose() => _handle.Dispose();
}

/// <summary>
/// The Summary Information stream of an MSI. String properties are written as
/// VT_LPSTR and integer ones (PageCount, WordCount, Security) as VT_I4, the
/// types the Windows Installer schema gives them.
/// </summary>
public sealed class MsiSummaryInfo : IDisposable
{
    public const uint PID_TITLE = 2;
    public const uint PID_SUBJECT = 3;
    public const uint PID_AUTHOR = 4;
    public const uint PID_COMMENTS = 6;
    public const uint PID_TEMPLATE = 7;
    public const uint PID_REVNUMBER = 9;
    public const uint PID_PAGECOUNT = 14;
    public const uint PID_WORDCOUNT = 15;
    public const uint PID_APPNAME = 18;
    public const uint PID_SECURITY = 19;

    // The most properties one update may change; the Windows Installer schema defines 20.
    private const uint MaxUpdates = 20;

    private readonly MsiHandle _handle;

    internal MsiSummaryInfo(MsiHandle handle) => _handle = handle;

    /// <summary>Opens the summary stream of the MSI at <paramref name="path"/>, writable when <paramref name="enableWrite"/>.</summary>
    public static MsiSummaryInfo Open(string path, bool enableWrite)
    {
        MsiNative.Check(MsiNative.MsiGetSummaryInformationW(
            IntPtr.Zero, path, enableWrite ? MaxUpdates : 0, out var handle));
        return new MsiSummaryInfo(handle);
    }

    public void SetString(uint property, string value)
    {
        long time = 0;
        MsiNative.Check(MsiNative.MsiSummaryInfoSetPropertyW(_handle, property, MsiNative.VT_LPSTR, 0, ref time, value));
    }

    public void SetInteger(uint property, int value)
    {
        long time = 0;
        MsiNative.Check(MsiNative.MsiSummaryInfoSetPropertyW(_handle, property, MsiNative.VT_I4, value, ref time, ""));
    }

    /// <summary>A string property, or "" when it is not set or not a string.</summary>
    public string GetString(uint property)
    {
        uint length = 256;
        var buffer = new StringBuilder((int)length);
        var result = MsiNative.MsiSummaryInfoGetPropertyW(_handle, property, out var type, out _, IntPtr.Zero, buffer, ref length);
        if (result == MsiNative.ERROR_MORE_DATA)
        {
            length++;
            buffer = new StringBuilder((int)length);
            result = MsiNative.MsiSummaryInfoGetPropertyW(_handle, property, out type, out _, IntPtr.Zero, buffer, ref length);
        }
        MsiNative.Check(result);
        return type == MsiNative.VT_LPSTR ? buffer.ToString() : string.Empty;
    }

    /// <summary>An integer property, or null when it is not set or not an integer.</summary>
    public int? GetInteger(uint property)
    {
        uint length = 0;
        var result = MsiNative.MsiSummaryInfoGetPropertyW(_handle, property, out var type, out var value, IntPtr.Zero, new StringBuilder(1), ref length);
        if (result != MsiNative.ERROR_MORE_DATA)
        {
            MsiNative.Check(result);
        }
        return type is MsiNative.VT_I4 or MsiNative.VT_I2 ? value : null;
    }

    /// <summary>Writes the changed properties back to the MSI.</summary>
    public void Persist() => MsiNative.Check(MsiNative.MsiSummaryInfoPersist(_handle));

    public void Dispose() => _handle.Dispose();
}

/// <summary>An MSIHANDLE, closed with MsiCloseHandle.</summary>
internal sealed class MsiHandle : SafeHandle
{
    public MsiHandle() : base(IntPtr.Zero, ownsHandle: true) { }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle() => MsiNative.MsiCloseHandle(handle) == 0;
}

internal static class MsiNative
{
    public const uint ERROR_MORE_DATA = 234;
    public const uint ERROR_NO_MORE_ITEMS = 259;
    public const int MSI_NULL_INTEGER = int.MinValue;
    public const int MSICONDITION_NONE = 2;
    public const int MSICONDITION_ERROR = 3;
    public const int MSIMODIFY_ASSIGN = 3;
    public const int MSICOLINFO_NAMES = 0;
    public const uint VT_I2 = 2;
    public const uint VT_I4 = 3;
    public const uint VT_LPSTR = 30;

    public static void Check(uint result)
    {
        if (result != 0)
        {
            throw new Win32Exception((int)result);
        }
    }

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiOpenDatabaseW(string databasePath, IntPtr persist, out MsiHandle database);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiDatabaseCommit(MsiHandle database);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int MsiDatabaseIsTablePersistentW(MsiHandle database, string tableName);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiDatabaseOpenViewW(MsiHandle database, string query, out MsiHandle view);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiViewExecute(MsiHandle view, IntPtr record);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiViewFetch(MsiHandle view, out MsiHandle record);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiViewModify(MsiHandle view, int mode, MsiHandle record);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiViewGetColumnInfo(MsiHandle view, int columnInfo, out MsiHandle record);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiViewClose(MsiHandle view);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern MsiHandle MsiCreateRecord(uint parameterCount);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiRecordGetFieldCount(MsiHandle record);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiRecordSetStringW(MsiHandle record, uint field, string value);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiRecordSetStreamW(MsiHandle record, uint field, string filePath);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiRecordGetStringW(MsiHandle record, uint field, StringBuilder value, ref uint length);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern int MsiRecordGetInteger(MsiHandle record, uint field);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiGetSummaryInformationW(MsiHandle database, string? databasePath, uint updateCount, out MsiHandle summaryInfo);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiGetSummaryInformationW(IntPtr database, string? databasePath, uint updateCount, out MsiHandle summaryInfo);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiSummaryInfoSetPropertyW(MsiHandle summaryInfo, uint property, uint dataType, int intValue, ref long fileTime, string value);

    [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern uint MsiSummaryInfoGetPropertyW(MsiHandle summaryInfo, uint property, out uint dataType, out int intValue, IntPtr fileTime, StringBuilder value, ref uint length);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiSummaryInfoPersist(MsiHandle summaryInfo);

    [DllImport("msi.dll", ExactSpelling = true)]
    public static extern uint MsiCloseHandle(IntPtr handle);
}
