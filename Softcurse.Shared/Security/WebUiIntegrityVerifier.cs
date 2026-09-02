using System.Security.Cryptography;

namespace Softcurse.Shared.Security;

public static class WebUiIntegrityVerifier
{
    public static WebUiIntegrityResult Verify(string webUiRoot, Stream manifestStream)
    {
        if (string.IsNullOrWhiteSpace(webUiRoot))
            return WebUiIntegrityResult.Failed("WebUI root is required.");
        if (!Directory.Exists(webUiRoot))
            return WebUiIntegrityResult.Failed("WebUI directory is missing.");

        try
        {
            var root = Path.GetFullPath(webUiRoot);
            if (File.GetAttributes(root).HasFlag(FileAttributes.ReparsePoint))
                return WebUiIntegrityResult.Failed("WebUI root cannot be a reparse point.");

            var expected = ReadManifest(root, manifestStream);
            var actual = EnumerateFilesWithoutReparsePoints(root);
            var unexpected = actual.Keys.Except(expected.Keys, StringComparer.OrdinalIgnoreCase).Order().FirstOrDefault();
            if (unexpected is not null)
                return WebUiIntegrityResult.Failed($"Unexpected WebUI file: {unexpected}");
            var missing = expected.Keys.Except(actual.Keys, StringComparer.OrdinalIgnoreCase).Order().FirstOrDefault();
            if (missing is not null)
                return WebUiIntegrityResult.Failed($"Missing WebUI file: {missing}");

            foreach (var (relativePath, expectedHash) in expected)
            {
                using var file = File.OpenRead(actual[relativePath]);
                var actualHash = Convert.ToHexString(SHA256.HashData(file)).ToLowerInvariant();
                if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(expectedHash),
                        Convert.FromHexString(actualHash)))
                    return WebUiIntegrityResult.Failed($"WebUI integrity mismatch: {relativePath}");
            }

            return new WebUiIntegrityResult(true, $"Verified {expected.Count} WebUI files.", expected.Count);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or FormatException)
        {
            return WebUiIntegrityResult.Failed(ex.Message);
        }
    }

    private static Dictionary<string, string> ReadManifest(string root, Stream stream)
    {
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StreamReader(stream, leaveOpen: true);
        while (reader.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var separator = line.IndexOf('|');
            if (separator != 64 || line.Length <= 65)
                throw new InvalidDataException("WebUI integrity manifest contains a malformed record.");
            var hash = line[..separator].ToLowerInvariant();
            if (!hash.All(Uri.IsHexDigit))
                throw new InvalidDataException("WebUI integrity manifest contains an invalid SHA-256 value.");
            var relativePath = NormalizeRelativePath(line[(separator + 1)..]);
            var fullPath = Path.GetFullPath(Path.Combine(root, relativePath));
            EnsureWithinRoot(root, fullPath);
            if (!expected.TryAdd(relativePath, hash))
                throw new InvalidDataException($"WebUI integrity manifest contains a duplicate path: {relativePath}");
        }
        if (expected.Count == 0)
            throw new InvalidDataException("WebUI integrity manifest is empty.");
        return expected;
    }

    private static Dictionary<string, string> EnumerateFilesWithoutReparsePoints(string root)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Queue<string>();
        pending.Enqueue(root);
        while (pending.TryDequeue(out var directory))
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidDataException($"WebUI contains a reparse point: {Path.GetRelativePath(root, entry)}");
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    pending.Enqueue(entry);
                    continue;
                }
                var relativePath = NormalizeRelativePath(Path.GetRelativePath(root, entry));
                if (!files.TryAdd(relativePath, entry))
                    throw new InvalidDataException($"WebUI contains a duplicate path: {relativePath}");
            }
        }
        return files;
    }

    private static string NormalizeRelativePath(string path)
    {
        var normalized = path.Trim().Replace('\\', '/');
        if (normalized.Length == 0 || Path.IsPathRooted(normalized) ||
            normalized.Split('/').Any(component => component is "" or "." or ".."))
            throw new InvalidDataException("WebUI integrity manifest contains an unsafe path.");
        return normalized;
    }

    private static void EnsureWithinRoot(string root, string path)
    {
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("WebUI integrity manifest path escapes the WebUI root.");
    }
}

public sealed record WebUiIntegrityResult(bool Success, string Message, int VerifiedFileCount)
{
    public static WebUiIntegrityResult Failed(string message) => new(false, message, 0);
}
