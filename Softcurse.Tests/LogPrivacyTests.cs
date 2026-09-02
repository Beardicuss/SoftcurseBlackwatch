using Softcurse.Shared.Logging;
using System.IO.Compression;
using System.Text.Json;
using Xunit;

namespace Softcurse.Tests;

public sealed class LogPrivacyTests
{
    [Fact]
    public void Redact_RemovesSecretsQueriesAndUserProfile()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var input = $"Path={profile}\\private\\file.exe token=abc123 https://example.test/path?q=secret\nforged";

        var result = LogRedactor.Redact(input);

        Assert.DoesNotContain(profile, result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("abc123", result);
        Assert.DoesNotContain("q=secret", result);
        Assert.DoesNotContain('\n', result);
        Assert.Contains("%USERPROFILE%", result);
        Assert.Contains("token=[REDACTED]", result);
    }

    [Fact]
    public void Retention_DeletesExpiredAndThenOldestFilesOnly()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"blackwatch-retention-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var now = DateTime.UtcNow;
            WriteLog(directory, "blackwatch_expired.log", 8, now.AddDays(-20));
            WriteLog(directory, "blackwatch_old.log", 8, now.AddDays(-2));
            WriteLog(directory, "blackwatch_new.log", 8, now.AddDays(-1));
            File.WriteAllText(Path.Combine(directory, "unrelated.txt"), "preserve");

            var deleted = LogRetentionPolicy.Apply(directory, TimeSpan.FromDays(14), 8, now);

            Assert.Equal(2, deleted);
            Assert.False(File.Exists(Path.Combine(directory, "blackwatch_expired.log")));
            Assert.False(File.Exists(Path.Combine(directory, "blackwatch_old.log")));
            Assert.True(File.Exists(Path.Combine(directory, "blackwatch_new.log")));
            Assert.True(File.Exists(Path.Combine(directory, "unrelated.txt")));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void Logger_RedactsBeforeBufferAndDisk()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"blackwatch-logger-{Guid.NewGuid():N}");
        try
        {
            using (var logger = new BlackwatchLogger(directory))
            {
                logger.Info("Test\nSource", "password=hunter2");
                Assert.DoesNotContain("hunter2", logger.GetBuffer().Single().Message);
            }
            Assert.DoesNotContain("hunter2", File.ReadAllText(Directory.GetFiles(directory, "*.log").Single()));
        }
        finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void DiagnosticExport_RedactsHistoricalLogContent()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"blackwatch-diagnostics-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var destination = Path.Combine(directory, "bundle.zip");
        try
        {
            var logs = Path.Combine(directory, "logs");
            Directory.CreateDirectory(logs);
            File.WriteAllText(Path.Combine(logs, "blackwatch_history.log"), "authorization=raw-secret");
            DiagnosticBundleExporter.Export(destination, logs, new DiagnosticSummary("1.0.0", "Healthy", "OK", DateTime.UtcNow, true, 10, 0, 3));

            using var archive = ZipFile.OpenRead(destination);
            var logEntry = Assert.Single(archive.Entries, entry => entry.FullName.StartsWith("logs/", StringComparison.Ordinal));
            using var reader = new StreamReader(logEntry.Open());
            var contents = reader.ReadToEnd();
            Assert.DoesNotContain("raw-secret", contents);
            Assert.Contains("authorization=[REDACTED]", contents);
            var summaryEntry = Assert.Single(archive.Entries, entry => entry.FullName == "diagnostic-summary.json");
            using var summaryReader = new StreamReader(summaryEntry.Open());
            using var document = JsonDocument.Parse(summaryReader.ReadToEnd());
            Assert.Equal("1.0.0", document.RootElement.GetProperty("ProductVersion").GetString());
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    private static void WriteLog(string directory, string name, int bytes, DateTime lastWriteUtc)
    {
        var path = Path.Combine(directory, name);
        File.WriteAllText(path, new string('x', bytes));
        File.SetLastWriteTimeUtc(path, lastWriteUtc);
    }
}
