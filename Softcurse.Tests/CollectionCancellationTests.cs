using Softcurse.Core.Detection;
using Softcurse.Core.Scanning;
using Softcurse.Monitor;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class CollectionCancellationTests
{
    [Fact]
    public void ProcessScanner_RejectsPreCanceledScan()
    {
        using var logger = new BlackwatchLogger();
        var scanner = new ProcessScanner(logger);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => scanner.ScanAll(cancellation.Token));
    }

    [Fact]
    public void NetworkMonitor_RejectsPreCanceledCollection()
    {
        using var logger = new BlackwatchLogger();
        using var monitor = new NetworkMonitor(logger);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => monitor.GetConnections(cancellationToken: cancellation.Token));
    }

    [Fact]
    public void ThreatScorer_StopsBetweenProcesses()
    {
        using var logger = new BlackwatchLogger();
        var scorer = new ThreatScorer(logger, new BlackwatchConfig());
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => scorer.ScoreAll([new ProcessInfo { Pid = 1, Name = "test" }], cancellation.Token));
    }
}
