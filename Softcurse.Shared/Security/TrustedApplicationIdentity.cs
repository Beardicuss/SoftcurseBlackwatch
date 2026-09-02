using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Softcurse.Shared.Config;

namespace Softcurse.Shared.Security;

public static class TrustedApplicationIdentity
{
    public static TrustedApplication Inspect(string executablePath, string reason = "User selected this executable.")
    {
        if (string.IsNullOrWhiteSpace(executablePath))
            throw new ArgumentException("Executable path is required.", nameof(executablePath));
        var canonicalPath = Path.GetFullPath(executablePath);
        if (!File.Exists(canonicalPath))
            throw new FileNotFoundException("Trusted executable was not found.", canonicalPath);

        using var stream = File.OpenRead(canonicalPath);
        var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        var version = FileVersionInfo.GetVersionInfo(canonicalPath);
        return new TrustedApplication
        {
            TrustId = Guid.NewGuid().ToString("N"),
            Name = Path.GetFileNameWithoutExtension(canonicalPath),
            CanonicalPath = canonicalPath,
            Sha256 = hash,
            PublisherThumbprint = ReadPublisherThumbprint(canonicalPath),
            ProductName = version.ProductName ?? string.Empty,
            CompanyName = version.CompanyName ?? string.Empty,
            Reason = reason,
            CreatedUtc = DateTime.UtcNow
        };
    }

    private static string ReadPublisherThumbprint(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = X509Certificate2.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057
            using var normalized = new X509Certificate2(certificate);
            return normalized.Thumbprint ?? string.Empty;
        }
        catch (CryptographicException) { return string.Empty; }
    }
}
