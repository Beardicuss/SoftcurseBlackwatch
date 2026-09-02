using System.Diagnostics;
using Softcurse.Cleaner;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class BlackwatchCleanerTests : IDisposable
{
    private readonly string _testRoot = Path.Combine(
        Path.GetTempPath(), $"blackwatch-tests-{Guid.NewGuid():N}");

    [Fact]
    public void KillProcess_RejectsChangedProcessIdentity()
    {
        var config = new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_testRoot, "quarantine")
        };
        using var logger = new BlackwatchLogger(Path.Combine(_testRoot, "logs"));
        var journal = new ActionJournal(Path.Combine(_testRoot, "journal", "actions.jsonl"));
        var cleaner = new BlackwatchCleaner(logger, config, journal);
        using var current = Process.GetCurrentProcess();
        var authorization = cleaner.AuthorizeProcessKill(
            current.Id,
            "not-the-current-process",
            current.StartTime);

        var action = cleaner.KillProcess(
            current.Id,
            "not-the-current-process",
            current.StartTime,
            dryRun: false,
            authorization);

        Assert.False(action.Success);
        Assert.Contains("identity changed", action.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.False(current.HasExited);
        Assert.Equal(CleanerActionStatus.Failed, action.Status);
        Assert.Equal(2, journal.ReadRecords().Count);
    }

    [Fact]
    public void KillProcess_RejectsLiveMutationWithoutAuthorization()
    {
        var config = new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_testRoot, "quarantine")
        };
        using var logger = new BlackwatchLogger(Path.Combine(_testRoot, "logs"));
        var journal = new ActionJournal(Path.Combine(_testRoot, "journal", "actions.jsonl"));
        var cleaner = new BlackwatchCleaner(logger, config, journal);
        using var current = Process.GetCurrentProcess();

        var action = cleaner.KillProcess(current.Id, current.ProcessName, current.StartTime, dryRun: false);

        Assert.False(action.Success);
        Assert.Contains("authorization", action.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.False(current.HasExited);
        Assert.Equal(CleanerActionStatus.Failed, action.Status);
        Assert.Equal(2, journal.ReadRecords().Count);
    }

    [Fact]
    public void KillProcess_RejectsProtectedWindowsProcessEvenWithAuthorization()
    {
        var config = new BlackwatchConfig
        {
            DryRunMode = false,
            QuarantinePath = Path.Combine(_testRoot, "quarantine")
        };
        using var logger = new BlackwatchLogger(Path.Combine(_testRoot, "logs"));
        var journal = new ActionJournal(Path.Combine(_testRoot, "journal", "actions.jsonl"));
        var cleaner = new BlackwatchCleaner(logger, config, journal);
        using var current = Process.GetCurrentProcess();
        var authorization = cleaner.AuthorizeProcessKill(current.Id, "lsass", current.StartTime);

        var action = cleaner.KillProcess(current.Id, "lsass", current.StartTime, dryRun: false, authorization);

        Assert.False(action.Success);
        Assert.Contains("protected Windows process", action.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.False(current.HasExited);
        Assert.Equal(CleanerActionStatus.Failed, action.Status);
        Assert.Equal(2, journal.ReadRecords().Count);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testRoot))
            Directory.Delete(_testRoot, recursive: true);
    }
}
