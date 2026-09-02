using System.Text.Json;
using Softcurse.Cleaner;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class QuarantineTransactionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-quarantine-{Guid.NewGuid():N}");

    [Fact]
    public void QuarantineAndRestore_RoundTripWithManifestAndJournal()
    {
        var original = Path.Combine(_root, "source", "fixture.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        File.WriteAllText(original, "fixture-content");
        var (cleaner, journal, logger) = CreateCleaner();
        using (logger)
        {
            var quarantine = cleaner.QuarantineFile(original);

            Assert.True(quarantine.Success);
            Assert.False(File.Exists(original));
            Assert.True(File.Exists(quarantine.QuarantinePath));
            var manifestPath = quarantine.QuarantinePath + ".manifest.json";
            Assert.True(File.Exists(manifestPath));

            var restored = cleaner.RestoreFromQuarantine(quarantine);

            Assert.True(restored);
            Assert.Equal("fixture-content", File.ReadAllText(original));
            var manifest = JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(manifestPath));
            Assert.NotNull(manifest?.RestoredUtc);
            Assert.Equal(4, journal.ReadRecords().Count);
            Assert.Empty(journal.GetIncompleteActions());
        }
    }

    [Fact]
    public void Restore_RejectsTamperedQuarantineFile()
    {
        var original = Path.Combine(_root, "source", "fixture.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(original)!);
        File.WriteAllText(original, "original-content");
        var (cleaner, journal, logger) = CreateCleaner();
        using (logger)
        {
            var quarantine = cleaner.QuarantineFile(original);
            File.WriteAllText(quarantine.QuarantinePath!, "tampered-content");

            var restored = cleaner.RestoreFromQuarantine(quarantine);

            Assert.False(restored);
            Assert.False(File.Exists(original));
            Assert.Equal(CleanerActionStatus.Failed, cleaner.ActionLog[^1].Status);
            Assert.Contains("hash", cleaner.ActionLog[^1].ErrorMessage, StringComparison.OrdinalIgnoreCase);
            Assert.Empty(journal.GetIncompleteActions());
        }
    }

    private (BlackwatchCleaner Cleaner, ActionJournal Journal, BlackwatchLogger Logger) CreateCleaner()
    {
        var config = new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_root, "quarantine")
        };
        var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        return (new BlackwatchCleaner(logger, config, journal), journal, logger);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
