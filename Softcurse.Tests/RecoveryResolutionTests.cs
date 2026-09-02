using Softcurse.Cleaner;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class RecoveryResolutionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-resolution-{Guid.NewGuid():N}");

    [Theory]
    [InlineData(true, ActionJournalEvent.Completed)]
    [InlineData(false, ActionJournalEvent.Failed)]
    public void ResolveRecovery_AppendsExplicitTerminalDecision(bool completed, ActionJournalEvent expectedEvent)
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        var interrupted = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42, TargetName = "fixture" };
        journal.Prepare(interrupted);
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = new BlackwatchCleaner(logger, new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_root, "quarantine")
        }, journal);
        Assert.Single(cleaner.RecoveryRequiredActions);

        var kind = completed ? RecoveryActionKind.Finalize : RecoveryActionKind.Dismiss;
        var authorization = cleaner.AuthorizeRecovery(interrupted.ActionId, kind);
        var resolved = cleaner.ResolveRecovery(interrupted.ActionId, completed, "Explicit test disposition.", kind, authorization);

        Assert.True(resolved);
        Assert.Empty(cleaner.RecoveryRequiredActions);
        Assert.Equal(expectedEvent, journal.ReadRecords()[^1].Event);
        Assert.Contains("Explicit test disposition", journal.ReadRecords()[^1].Action.ErrorMessage);
    }

    [Fact]
    public void ResolveRecovery_RejectsUnknownActionId()
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = new BlackwatchCleaner(logger, new BlackwatchConfig { QuarantinePath = Path.Combine(_root, "quarantine") }, journal);
        Assert.False(cleaner.ResolveRecovery("unknown", true, "test", RecoveryActionKind.Finalize, null));
    }

    [Fact]
    public void ResolveRecovery_RejectsMissingAuthorizationAndPreservesPendingAction()
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        var interrupted = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42, TargetName = "fixture" };
        journal.Prepare(interrupted);
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = CreateCleaner(logger, journal);

        var resolved = cleaner.ResolveRecovery(
            interrupted.ActionId,
            completed: true,
            "Unauthorized disposition.",
            RecoveryActionKind.Finalize,
            authorization: null);

        Assert.False(resolved);
        Assert.Single(cleaner.RecoveryRequiredActions);
        Assert.Single(journal.ReadRecords());
    }

    [Fact]
    public void ResolveRecovery_RejectsAuthorizationForDifferentOperation()
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        var interrupted = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42, TargetName = "fixture" };
        journal.Prepare(interrupted);
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = CreateCleaner(logger, journal);
        var dismissAuthorization = cleaner.AuthorizeRecovery(interrupted.ActionId, RecoveryActionKind.Dismiss);

        var resolved = cleaner.ResolveRecovery(
            interrupted.ActionId,
            completed: true,
            "Cross-scope disposition.",
            RecoveryActionKind.Finalize,
            dismissAuthorization);

        Assert.False(resolved);
        Assert.Single(cleaner.RecoveryRequiredActions);
        Assert.Single(journal.ReadRecords());
    }

    [Fact]
    public void ResolveRecovery_RejectsAuthorizationBoundToDifferentActionId()
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        var first = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 41, TargetName = "first" };
        var second = new CleanerAction { ActionType = CleanerActionType.KillProcess, TargetPid = 42, TargetName = "second" };
        journal.Prepare(first);
        journal.Prepare(second);
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = CreateCleaner(logger, journal);
        var authorization = cleaner.AuthorizeRecovery(first.ActionId, RecoveryActionKind.Finalize);

        var resolved = cleaner.ResolveRecovery(
            second.ActionId,
            completed: true,
            "Wrong target disposition.",
            RecoveryActionKind.Finalize,
            authorization);

        Assert.False(resolved);
        Assert.Equal(2, cleaner.RecoveryRequiredActions.Count);
        Assert.Equal(2, journal.ReadRecords().Count);
    }

    [Fact]
    public void RestoreRecovery_RejectsMissingAuthorizationBeforeFileMutation()
    {
        var journal = new ActionJournal(Path.Combine(_root, "journal", "actions.jsonl"));
        var interrupted = new CleanerAction
        {
            ActionType = CleanerActionType.QuarantineFile,
            TargetName = "fixture.exe",
            TargetPath = Path.Combine(_root, "original", "fixture.exe"),
            QuarantinePath = Path.Combine(_root, "quarantine", "fixture.quarantine")
        };
        journal.Prepare(interrupted);
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var cleaner = CreateCleaner(logger, journal);

        Assert.False(cleaner.RestoreRecovery(interrupted.ActionId, authorization: null));
        Assert.Single(cleaner.RecoveryRequiredActions);
        Assert.Single(journal.ReadRecords());
        Assert.False(File.Exists(interrupted.TargetPath));
    }

    private BlackwatchCleaner CreateCleaner(BlackwatchLogger logger, ActionJournal journal) =>
        new(logger, new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_root, "quarantine")
        }, journal);

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
