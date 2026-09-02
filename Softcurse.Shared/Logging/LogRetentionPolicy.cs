namespace Softcurse.Shared.Logging;

public static class LogRetentionPolicy
{
    public static int Apply(string directory, TimeSpan maxAge, long maxTotalBytes, DateTime utcNow)
    {
        if (!Directory.Exists(directory)) return 0;
        if (maxAge <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(maxAge));
        if (maxTotalBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxTotalBytes));

        var deleted = 0;
        var files = Directory.EnumerateFiles(directory, "blackwatch_*.log", SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .Where(file => (file.Attributes & FileAttributes.ReparsePoint) == 0)
            .OrderBy(file => file.LastWriteTimeUtc)
            .ToList();

        foreach (var expired in files.Where(file => utcNow - file.LastWriteTimeUtc > maxAge).ToList())
        {
            expired.Delete();
            files.Remove(expired);
            deleted++;
        }

        var totalBytes = files.Sum(file => file.Length);
        foreach (var oldest in files)
        {
            if (totalBytes <= maxTotalBytes) break;
            totalBytes -= oldest.Length;
            oldest.Delete();
            deleted++;
        }
        return deleted;
    }
}
