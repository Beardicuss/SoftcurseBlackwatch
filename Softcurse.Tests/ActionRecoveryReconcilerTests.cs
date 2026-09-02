using System.Security.Cryptography;
using System.Text.Json;
using Softcurse.Cleaner;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class ActionRecoveryReconcilerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-recovery-{Guid.NewGuid():N}");

    [Fact]
    public void Reconcile_FinalizesCompletedQuarantineWithValidManifest()
    {
        var (journal, action) = PreparedQuarantine(sourceExists: false, quarantineExists: true, validHash: true);

        var results = new ActionRecoveryReconciler(journal).Reconcile();

        Assert.Equal(RecoveryDisposition.Completed, Assert.Single(results).Disposition);
        Assert.Empty(journal.GetIncompleteActions());
        Assert.Equal(ActionJournalEvent.Completed, journal.ReadRecords()[^1].Event);
    }

    [Fact]
    public void Reconcile_FinalizesQuarantineThatNeverStarted()
    {
        var (journal, _) = PreparedQuarantine(sourceExists: true, quarantineExists: false, validHash: true);

        var result = Assert.Single(new ActionRecoveryReconciler(journal).Reconcile());

        Assert.Equal(RecoveryDisposition.NotStarted, result.Disposition);
        Assert.Empty(journal.GetIncompleteActions());
        Assert.Equal(ActionJournalEvent.Failed, journal.ReadRecords()[^1].Event);
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(false, false, true)]
    [InlineData(false, true, false)]
    public void Reconcile_LeavesAmbiguousOrInvalidStateForManualReview(bool sourceExists, bool quarantineExists, bool validHash)
    {
        var (journal, action) = PreparedQuarantine(sourceExists, quarantineExists, validHash);

        var result = Assert.Single(new ActionRecoveryReconciler(journal).Reconcile());

        Assert.Equal(RecoveryDisposition.ManualReview, result.Disposition);
        Assert.Equal(action.ActionId, Assert.Single(journal.GetIncompleteActions()).ActionId);
    }

    [Fact]
    public void Reconcile_DoesNotGuessProcessTerminationOutcome()
    {
        var journal = Journal();
        journal.Prepare(new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42, TargetName = "fixture" });

        var result = Assert.Single(new ActionRecoveryReconciler(journal).Reconcile());

        Assert.Equal(RecoveryDisposition.ManualReview, result.Disposition);
        Assert.Single(journal.GetIncompleteActions());
    }

    private (ActionJournal Journal, CleanerAction Action) PreparedQuarantine(bool sourceExists, bool quarantineExists, bool validHash)
    {
        Directory.CreateDirectory(_root);
        var source = Path.Combine(_root, "source.exe");
        var quarantine = Path.Combine(_root, "quarantine", "source.quarantine");
        Directory.CreateDirectory(Path.GetDirectoryName(quarantine)!);
        const string content = "original-content";
        if (sourceExists) File.WriteAllText(source, content);
        if (quarantineExists) File.WriteAllText(quarantine, validHash ? content : "tampered");
        var action = new CleanerAction
        {
            ActionType = CleanerActionType.QuarantineFile,
            TargetName = "source.exe",
            TargetPath = source,
            QuarantinePath = quarantine
        };
        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        var manifest = new QuarantineManifest
        {
            ActionId = action.ActionId,
            OriginalPath = source,
            QuarantinePath = quarantine,
            OriginalLength = content.Length,
            OriginalSha256 = hash,
            QuarantinedUtc = DateTime.UtcNow
        };
        File.WriteAllText(quarantine + ".manifest.json", JsonSerializer.Serialize(manifest));
        var journal = Journal();
        journal.Prepare(action);
        return (journal, action);
    }

    private ActionJournal Journal() => new(Path.Combine(_root, "journal", "actions.jsonl"));

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
