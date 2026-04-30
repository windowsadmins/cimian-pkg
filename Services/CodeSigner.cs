using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Cimian.CLI.Cimipkg.Models;
using Microsoft.Extensions.Logging;

namespace Cimian.CLI.Cimipkg.Services;

/// <summary>
/// Handles code signing for PowerShell scripts and NuGet packages.
/// </summary>
public class CodeSigner
{
    private readonly ILogger<CodeSigner> _logger;

    public CodeSigner(ILogger<CodeSigner> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Signs all PowerShell scripts in a directory using Authenticode.
    /// </summary>
    /// <param name="directory">Directory containing scripts to sign.</param>
    /// <param name="certSubject">Certificate subject name (CN=...).</param>
    /// <param name="certThumbprint">Certificate thumbprint (optional, takes precedence).</param>
    public void SignPowerShellScriptsInDirectory(string directory, string? certSubject, string? certThumbprint)
    {
        if (string.IsNullOrEmpty(certSubject) && string.IsNullOrEmpty(certThumbprint))
        {
            _logger.LogDebug("No signing certificate specified, skipping script signing");
            return;
        }

        if (!Directory.Exists(directory))
        {
            _logger.LogWarning("Directory does not exist: {Directory}", directory);
            return;
        }

        var ps1Files = Directory.GetFiles(directory, "*.ps1", SearchOption.AllDirectories);
        foreach (var scriptPath in ps1Files)
        {
            SignPowerShellScript(scriptPath, certSubject, certThumbprint);
        }

        _logger.LogInformation("Signed {Count} PowerShell script(s) in {Directory}", ps1Files.Length, directory);
    }

    /// <summary>
    /// Signs a single PowerShell script using signtool.exe directly.
    /// Uses signtool instead of PowerShell's Set-AuthenticodeSignature to avoid
    /// Cert: drive availability issues when launched as a subprocess from .NET.
    /// </summary>
    /// <param name="scriptPath">Path to the script to sign.</param>
    /// <param name="certSubject">Certificate subject name.</param>
    /// <param name="certThumbprint">Certificate thumbprint (optional, takes precedence).</param>
    public void SignPowerShellScript(string scriptPath, string? certSubject, string? certThumbprint)
    {
        if (!File.Exists(scriptPath))
        {
            throw new FileNotFoundException("Script file not found.", scriptPath);
        }

        var signtoolPath = FindSignTool();

        // Build signtool arguments matching the Go implementation
        var args = new StringBuilder("sign ");

        if (!string.IsNullOrEmpty(certThumbprint))
        {
            args.Append($"/sha1 {certThumbprint} ");
            _logger.LogDebug("Signing {Script} with thumbprint: {Thumbprint}", Path.GetFileName(scriptPath), certThumbprint);
        }
        else if (!string.IsNullOrEmpty(certSubject))
        {
            args.Append($"/n \"{certSubject}\" ");
            _logger.LogDebug("Signing {Script} with certificate: {Subject}", Path.GetFileName(scriptPath), certSubject);
        }
        else
        {
            throw new InvalidOperationException($"No certificate specified for {scriptPath}");
        }

        args.Append("/fd SHA256 ");
        args.Append("/tr http://timestamp.digicert.com ");
        args.Append("/td SHA256 ");
        args.Append($"\"{scriptPath}\"");

        var psi = new ProcessStartInfo
        {
            FileName = signtoolPath,
            Arguments = args.ToString(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        if (process == null)
        {
            throw new InvalidOperationException("Failed to start signtool.exe process");
        }

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Failed to sign script {scriptPath}: {error}{output}");
        }

        _logger.LogDebug("Signed script: {ScriptPath}", scriptPath);
    }

    /// <summary>
    /// Signs a NuGet package (.nupkg or .pkg) using nuget sign.
    /// </summary>
    /// <param name="packagePath">Path to the package to sign.</param>
    /// <param name="certSubject">Certificate subject name.</param>
    public void SignNuGetPackage(string packagePath, string certSubject)
    {
        if (!File.Exists(packagePath))
        {
            throw new FileNotFoundException("Package file not found.", packagePath);
        }

        // Try using nuget sign command
        var psi = new ProcessStartInfo
        {
            FileName = "nuget",
            Arguments = $"sign \"{packagePath}\" -CertificateSubjectName \"{certSubject}\" -Timestamper http://timestamp.digicert.com",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(psi);
            if (process == null)
            {
                _logger.LogWarning("Failed to start nuget sign process. Package will not be signed.");
                return;
            }

            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                var error = process.StandardError.ReadToEnd();
                _logger.LogWarning("nuget sign failed: {Error}", error);
                _logger.LogWarning("Package {PackagePath} was not signed", packagePath);
            }
            else
            {
                _logger.LogInformation("Package signed: {PackagePath}", packagePath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sign package (nuget may not be available)");
        }
    }

    /// <summary>
    /// Gets certificate information from the certificate store.
    /// </summary>
    /// <param name="certSubject">Certificate subject name to search for.</param>
    /// <param name="certThumbprint">Certificate thumbprint to search for (takes precedence).</param>
    /// <returns>Certificate information if found.</returns>
    public CertificateInfo? GetCertificateInfo(string? certSubject, string? certThumbprint)
    {
        if (string.IsNullOrEmpty(certSubject) && string.IsNullOrEmpty(certThumbprint))
        {
            return null;
        }

        // Try CurrentUser store first, then LocalMachine
        var storeLocations = new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine };

        foreach (var storeLocation in storeLocations)
        {
            using var store = new X509Store(StoreName.My, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates)
                {
                    // Match by thumbprint if provided
                    if (!string.IsNullOrEmpty(certThumbprint))
                    {
                        if (string.Equals(cert.Thumbprint, certThumbprint, StringComparison.OrdinalIgnoreCase))
                        {
                            return CreateCertificateInfo(cert);
                        }
                    }
                    // Match by subject
                    else if (!string.IsNullOrEmpty(certSubject))
                    {
                        if (cert.Subject.Contains(certSubject, StringComparison.OrdinalIgnoreCase))
                        {
                            return CreateCertificateInfo(cert);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to access certificate store: {StoreLocation}", storeLocation);
            }
        }

        return null;
    }

    /// <summary>
    /// Creates a package signature for embedding in build-info.yaml.
    /// </summary>
    /// <param name="packageDir">Directory containing package contents.</param>
    /// <param name="certSubject">Certificate subject name.</param>
    /// <param name="certThumbprint">Certificate thumbprint.</param>
    /// <returns>Package signature if certificate is found.</returns>
    public PackageSignature? CreatePackageSignature(string packageDir, string? certSubject, string? certThumbprint)
    {
        var certInfo = GetCertificateInfo(certSubject, certThumbprint);
        if (certInfo == null)
        {
            _logger.LogWarning("Could not find signing certificate");
            return null;
        }

        // Calculate content hash of all files in the package directory
        var contentHash = CalculateDirectoryHash(packageDir);

        // Create signed hash (content hash + thumbprint)
        using var sha256 = SHA256.Create();
        var signedHashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(contentHash + certInfo.Thumbprint));
        var signedHash = Convert.ToBase64String(signedHashBytes);

        return new PackageSignature
        {
            Algorithm = "SHA256",
            Certificate = certInfo,
            PackageHash = contentHash,
            ContentHash = contentHash,
            SignedHash = signedHash,
            Timestamp = DateTime.UtcNow.ToString("O"),
            Version = "1.0"
        };
    }

    /// <summary>
    /// Calculates a combined hash of all files in a directory.
    /// </summary>
    private string CalculateDirectoryHash(string directory)
    {
        // Must match ZipArchiveHelper.CalculateContentHash() exactly:
        // - Forward slashes in paths (ZIP convention)
        // - SortedDictionary with OrdinalIgnoreCase for deterministic order
        // - Format: "path:hash|path:hash|" (pipe-separated with trailing pipe)
        var hashes = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var sha256 = SHA256.Create();

        foreach (var filePath in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
        {
            if (Path.GetFileName(filePath).Equals("build-info.yaml", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var relativePath = Path.GetRelativePath(directory, filePath).Replace('\\', '/');
            var fileBytes = File.ReadAllBytes(filePath);
            var fileHash = sha256.ComputeHash(fileBytes);
            hashes[relativePath] = Convert.ToHexString(fileHash).ToLowerInvariant();
        }

        var sb = new StringBuilder();
        foreach (var kvp in hashes)
        {
            sb.Append(kvp.Key);
            sb.Append(':');
            sb.Append(kvp.Value);
            sb.Append('|');
        }

        var combinedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
        return Convert.ToHexString(combinedHash).ToLowerInvariant();
    }

    /// <summary>
    /// Creates CertificateInfo from an X509Certificate2.
    /// </summary>
    private static CertificateInfo CreateCertificateInfo(X509Certificate2 cert)
    {
        return new CertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            SerialNumber = cert.SerialNumber,
            NotBefore = cert.NotBefore.ToString("O"),
            NotAfter = cert.NotAfter.ToString("O")
        };
    }

    /// <summary>
    /// Finds a signtool.exe the host OS can execute. Searches Windows SDK
    /// directories first (deterministic by arch), then PATH as a fallback.
    /// Validates each candidate via its PE header machine type — directory
    /// names like "x64" can lie on damaged installs, and a stale
    /// "arm64\signtool.exe" prepended to PATH on an x64 host would otherwise
    /// be picked silently and fail with "Machine Type Mismatch."
    /// Uses OSArchitecture (not ProcessArchitecture): we only need the
    /// host OS to be able to launch the resolved binary, not for it to
    /// share an architecture with this specific cimipkg process.
    /// </summary>
    private static string FindSignTool()
    {
        var osArch = RuntimeInformation.OSArchitecture;

        // Architecture preference for the host OS. x64 OS can launch x86;
        // arm64 OS can emulate x64/x86; x86 OS can only launch x86.
        var archPriority = osArch switch
        {
            Architecture.X64   => new[] { "x64", "x86" },
            Architecture.Arm64 => new[] { "arm64", "x64", "x86" },
            Architecture.X86   => new[] { "x86" },
            _                  => new[] { "x64", "x86" }
        };

        // Search Windows SDK \bin\<version>\<arch>\signtool.exe first.
        var sdkRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                         "Windows Kits", "10", "bin"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                         "Windows Kits", "10", "bin")
        };

        foreach (var sdkRoot in sdkRoots.Where(Directory.Exists))
        {
            var versionDirs = Directory.GetDirectories(sdkRoot, "10.*")
                .OrderByDescending(d => d);

            foreach (var versionDir in versionDirs)
            {
                foreach (var arch in archPriority)
                {
                    var candidate = Path.Combine(versionDir, arch, "signtool.exe");
                    if (File.Exists(candidate) && PeMachineRunnableOn(candidate, osArch))
                        return candidate;
                }
            }
        }

        // Fallback: walk PATH but validate each match via PE header. Protects
        // against a wrong-arch signtool ahead of the right one on PATH (e.g.
        // a Developer Prompt prepending an arm64 dir on x64 hosts).
        var pathSigntool = FindOnPath("signtool.exe", file => PeMachineRunnableOn(file, osArch));
        if (pathSigntool != null) return pathSigntool;

        throw new FileNotFoundException(
            "signtool.exe runnable on this host's OS architecture not found. " +
            "Install a Windows 10/11 SDK that includes the Signing Tools for your platform.");
    }

    /// <summary>
    /// Reads the machine-type field from a PE file's COFF header and returns
    /// true if the host OS at <paramref name="osArch"/> can execute it.
    /// Guards against directory-name lies and stale PATH entries.
    /// </summary>
    internal static bool PeMachineRunnableOn(string filePath, Architecture osArch)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            using var br = new BinaryReader(fs);
            // PE files: 4-byte int at offset 0x3C points to the PE header.
            if (fs.Length < 0x40) return false;
            fs.Seek(0x3C, SeekOrigin.Begin);
            var peOffset = br.ReadInt32();
            if (peOffset < 0 || fs.Length < peOffset + 6) return false;
            fs.Seek(peOffset, SeekOrigin.Begin);
            // PE signature: "PE\0\0"
            if (br.ReadByte() != 0x50 || br.ReadByte() != 0x45 ||
                br.ReadByte() != 0x00 || br.ReadByte() != 0x00)
                return false;
            var machine = br.ReadUInt16();
            // 0x8664 = AMD64, 0xAA64 = ARM64, 0x014C = I386
            return osArch switch
            {
                Architecture.X64   => machine is 0x8664 or 0x014C,
                Architecture.Arm64 => machine is 0xAA64 or 0x8664 or 0x014C,
                Architecture.X86   => machine is 0x014C,
                _                  => false
            };
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Walks $PATH and returns the first <paramref name="executable"/> match
    /// for which <paramref name="predicate"/> returns true (or the first
    /// match unconditionally if no predicate is supplied).
    /// </summary>
    private static string? FindOnPath(string executable, Func<string, bool>? predicate = null)
    {
        var pathVar = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(pathVar)) return null;

        foreach (var dir in pathVar.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var fullPath = Path.Combine(dir, executable);
            if (File.Exists(fullPath) && (predicate?.Invoke(fullPath) ?? true))
                return fullPath;
        }

        return null;
    }
}
