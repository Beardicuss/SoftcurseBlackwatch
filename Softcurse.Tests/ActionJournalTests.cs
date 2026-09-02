using Softcurse.Cleaner;
using Softcurse.Shared.Models;
using System.Text.Json;
using Xunit;

namespace Softcurse.Tests;

public sealed class ActionJournalTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-journal-{Guid.NewGuid():N}");
    private string JournalPath => Path.Combine(_root, "actions.jsonl");

    [Fact]
    public void PreparedAction_IsReportedForRecoveryAfterRestart()
    {
        var journal = new ActionJournal(JournalPath);
        var action = new CleanerAction { ActionType = CleanerActionType.QuarantineFile, TargetPath = @"C:\sample.exe" };
        journal.Prepare(action);

        var recovered = new ActionJournal(JournalPath).GetIncompleteActions();

        var pending = Assert.Single(recovered);
        Assert.Equal(action.ActionId, pending.ActionId);
        Assert.Equal(CleanerActionStatus.RecoveryRequired, pending.Status);
        Assert.Equal(action.TargetPath, pending.TargetPath);
    }

    [Fact]
    public void CompletedAction_IsNotReportedForRecovery()
    {
        var journal = new ActionJournal(JournalPath);
        var action = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42 };
        journal.Prepare(action);
        action.Success = true;
        journal.Complete(action);

        Assert.Empty(new ActionJournal(JournalPath).GetIncompleteActions());
        Assert.Equal(2, journal.ReadRecords().Count);
        Assert.Equal(CleanerActionStatus.Completed, action.Status);
    }

    [Fact]
    public void TruncatedFinalAppend_PreservesEarlierRecoveryRecord()
    {
        var journal = new ActionJournal(JournalPath);
        var action = new CleanerAction { ActionType = CleanerActionType.DisableAutorun, TargetName = "fixture" };
        journal.Prepare(action);
        File.AppendAllText(JournalPath, "{truncated");

        var pending = new ActionJournal(JournalPath).GetIncompleteActions();

        Assert.Single(pending);
        Assert.Equal(action.ActionId, pending[0].ActionId);
    }

    [Fact]
    public void CorruptionBeforeFinalLine_IsRejected()
    {
        var journal = new ActionJournal(JournalPath);
        journal.Prepare(new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 1 });
        var validLine = File.ReadAllText(JournalPath);
        File.WriteAllText(JournalPath, "{corrupt" + Environment.NewLine + validLine);

        var error = Assert.Throws<InvalidDataException>(() => new ActionJournal(JournalPath).ReadRecords());

        Assert.Contains("line 1", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Records_AreLinkedByVersionedHashes()
    {
        var journal = new ActionJournal(JournalPath);
        var action = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42 };
        journal.Prepare(action);
        action.Success = true;
        journal.Complete(action);

        var records = journal.ReadRecords();

        Assert.All(records, record =>
        {
            Assert.Equal(1, record.ChainVersion);
            Assert.Equal(64, record.RecordHash!.Length);
        });
        Assert.Equal("genesis", records[0].PreviousHash);
        Assert.Equal(records[0].RecordHash, records[1].PreviousHash);
    }

    [Fact]
    public void ValidJsonTampering_IsRejectedByHashChain()
    {
        var journal = new ActionJournal(JournalPath);
        journal.Prepare(new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 1 });
        var content = File.ReadAllText(JournalPath);
        Assert.Contains("\"TargetPid\":1", content);
        File.WriteAllText(JournalPath, content.Replace("\"TargetPid\":1", "\"TargetPid\":2", StringComparison.Ordinal));

        var error = Assert.Throws<InvalidDataException>(() => new ActionJournal(JournalPath).ReadRecords());

        Assert.Contains("record hash", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FirstChainedRecord_CommitsToLegacyPrefix()
    {
        Directory.CreateDirectory(_root);
        var legacyAction = new CleanerAction { ActionType = CleanerActionType.DisableAutorun, TargetName = "legacy" };
        var legacy = new ActionJournalRecord(
            legacyAction.ActionId,
            ActionJournalEvent.Prepared,
            DateTime.UtcNow,
            new CleanerActionSnapshot(
                legacyAction.ActionType, 0, legacyAction.TargetName, string.Empty,
                null, null, null, false, false, null));
        File.WriteAllText(JournalPath, JsonSerializer.Serialize(legacy) + Environment.NewLine);
        var journal = new ActionJournal(JournalPath);

        journal.Prepare(new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42 });
        var records = journal.ReadRecords();

        Assert.Equal(2, records.Count);
        Assert.Equal(0, records[0].ChainVersion);
        Assert.StartsWith("legacy:", records[1].PreviousHash, StringComparison.Ordinal);
        Assert.Equal(1, records[1].ChainVersion);
    }

    [Fact]
    public void Append_RepairsTruncatedTailBeforeContinuingChain()
    {
        var journal = new ActionJournal(JournalPath);
        var action = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42 };
        journal.Prepare(action);
        File.AppendAllText(JournalPath, "{truncated");
        action.Success = true;

        journal.Complete(action);

        var records = journal.ReadRecords();
        Assert.Equal(2, records.Count);
        Assert.Equal(records[0].RecordHash, records[1].PreviousHash);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
