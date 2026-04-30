using System.Runtime.InteropServices;
using Cimian.CLI.Cimipkg.Services;
using Xunit;

namespace Cimian.Tests.Cimipkg;

/// <summary>
/// Tests CodeSigner.PeMachineRunnableOn — the PE-header machine-type check
/// that protects FindSignTool from picking a wrong-arch signtool.exe (a
/// stale arm64 binary in PATH on an x64 host, an x64 binary in an SDK's
/// "arm64" directory, etc.). The method must reject malformed inputs and
/// correctly model which machine types each OS arch can launch.
/// </summary>
public class PeMachineRunnableOnTests
{
    // Authoritative machine-type values from winnt.h.
    private const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;
    private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    private const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;
    private const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;

    /// <summary>
    /// Writes a minimal PE-shaped byte sequence to a temp file: 0x3C points
    /// to a "PE\0\0" signature followed by a 2-byte machine type. That's
    /// the smallest input PeMachineRunnableOn reads — it does not parse the
    /// rest of the COFF/optional headers.
    /// </summary>
    private static string WriteMinimalPe(ushort machine, int peOffset = 0x80)
    {
        // Buffer must hold: e_lfanew at 0x3C, then "PE\0\0" + machine word
        // at peOffset. Pad up to peOffset + 6.
        var size = peOffset + 6;
        var buf = new byte[size];

        // e_lfanew (4 bytes, little-endian) at 0x3C
        buf[0x3C] = (byte)(peOffset & 0xFF);
        buf[0x3D] = (byte)((peOffset >> 8) & 0xFF);
        buf[0x3E] = (byte)((peOffset >> 16) & 0xFF);
        buf[0x3F] = (byte)((peOffset >> 24) & 0xFF);

        // "PE\0\0" at peOffset
        buf[peOffset + 0] = 0x50;
        buf[peOffset + 1] = 0x45;
        buf[peOffset + 2] = 0x00;
        buf[peOffset + 3] = 0x00;

        // Machine type (2 bytes, little-endian) at peOffset + 4
        buf[peOffset + 4] = (byte)(machine & 0xFF);
        buf[peOffset + 5] = (byte)((machine >> 8) & 0xFF);

        var path = Path.Combine(Path.GetTempPath(),
            $"pe-fixture-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, buf);
        return path;
    }

    public static IEnumerable<object[]> RunnableMatrix => new[]
    {
        // x64 OS: can launch amd64 and i386, not arm64.
        new object[] { IMAGE_FILE_MACHINE_AMD64, Architecture.X64,   true  },
        new object[] { IMAGE_FILE_MACHINE_I386,  Architecture.X64,   true  },
        new object[] { IMAGE_FILE_MACHINE_ARM64, Architecture.X64,   false },

        // arm64 OS: emulates everything we care about.
        new object[] { IMAGE_FILE_MACHINE_ARM64, Architecture.Arm64, true  },
        new object[] { IMAGE_FILE_MACHINE_AMD64, Architecture.Arm64, true  },
        new object[] { IMAGE_FILE_MACHINE_I386,  Architecture.Arm64, true  },

        // x86 OS: i386 only.
        new object[] { IMAGE_FILE_MACHINE_I386,  Architecture.X86,   true  },
        new object[] { IMAGE_FILE_MACHINE_AMD64, Architecture.X86,   false },
        new object[] { IMAGE_FILE_MACHINE_ARM64, Architecture.X86,   false },
    };

    [Theory]
    [MemberData(nameof(RunnableMatrix))]
    public void Returns_Expected_For_KnownMachineTypes(
        ushort machine, Architecture osArch, bool expected)
    {
        var path = WriteMinimalPe(machine);
        try
        {
            Assert.Equal(expected, CodeSigner.PeMachineRunnableOn(path, osArch));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_Unknown_MachineType_On_All_OsArchs()
    {
        var path = WriteMinimalPe(IMAGE_FILE_MACHINE_UNKNOWN);
        try
        {
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.Arm64));
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X86));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_File_Smaller_Than_DosHeader()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"pe-fixture-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, new byte[0x20]); // < 0x40
        try
        {
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_PeOffset_Pointing_Past_End_Of_File()
    {
        // Valid DOS header size, but e_lfanew points way beyond the buffer.
        var buf = new byte[0x80];
        buf[0x3C] = 0x00;
        buf[0x3D] = 0x10;
        buf[0x3E] = 0x00;
        buf[0x3F] = 0x00; // peOffset = 0x1000, file is only 0x80 bytes
        var path = Path.Combine(Path.GetTempPath(),
            $"pe-fixture-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, buf);
        try
        {
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_Negative_PeOffset()
    {
        var buf = new byte[0x80];
        // e_lfanew = -1 (0xFFFFFFFF as int32)
        buf[0x3C] = 0xFF;
        buf[0x3D] = 0xFF;
        buf[0x3E] = 0xFF;
        buf[0x3F] = 0xFF;
        var path = Path.Combine(Path.GetTempPath(),
            $"pe-fixture-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, buf);
        try
        {
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Rejects_Missing_Pe_Signature()
    {
        // Valid layout but the four bytes at peOffset are not "PE\0\0".
        var peOffset = 0x80;
        var size = peOffset + 6;
        var buf = new byte[size];
        buf[0x3C] = (byte)(peOffset & 0xFF);
        buf[0x3D] = (byte)((peOffset >> 8) & 0xFF);
        // "NE\0\0" instead of "PE\0\0"
        buf[peOffset + 0] = 0x4E;
        buf[peOffset + 1] = 0x45;
        buf[peOffset + 2] = 0x00;
        buf[peOffset + 3] = 0x00;
        buf[peOffset + 4] = 0x64;
        buf[peOffset + 5] = 0x86; // would be AMD64 if signature were valid

        var path = Path.Combine(Path.GetTempPath(),
            $"pe-fixture-{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(path, buf);
        try
        {
            Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Returns_False_When_File_Does_Not_Exist()
    {
        var path = Path.Combine(Path.GetTempPath(),
            $"does-not-exist-{Guid.NewGuid():N}.bin");
        Assert.False(CodeSigner.PeMachineRunnableOn(path, Architecture.X64));
    }
}
