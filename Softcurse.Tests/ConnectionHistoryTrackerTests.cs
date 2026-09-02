using Softcurse.Monitor;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public class ConnectionHistoryTrackerTests
{
    [Fact]
    public void Observe_PreservesFirstSeenAndIncrementsCount()
    {
        var tracker = new ConnectionHistoryTracker();
        var first = Connection(10, "10.0.0.1:5000", "203.0.113.1:443");
        var second = Connection(10, "10.0.0.1:5000", "203.0.113.1:443");
        var start = new DateTime(2026, 8, 31, 12, 0, 0, DateTimeKind.Utc);

        tracker.Observe(first, start);
        tracker.Observe(second, start.AddSeconds(5));

        Assert.Equal(first.ConnectionId, second.ConnectionId);
        Assert.Equal(start, second.FirstSeenUtc);
        Assert.Equal(start.AddSeconds(5), second.LastSeenUtc);
        Assert.Equal(2, second.ObservationCount);
    }

    [Fact]
    public void Observe_BoundsCapacityByEvictingOldestConnection()
    {
        var tracker = new ConnectionHistoryTracker(capacity: 2, retention: TimeSpan.FromHours(1));
        var start = DateTime.UtcNow;
        tracker.Observe(Connection(1, "a", "b"), start);
        tracker.Observe(Connection(2, "c", "d"), start.AddSeconds(1));
        tracker.Observe(Connection(3, "e", "f"), start.AddSeconds(2));

        Assert.Equal(2, tracker.Count);
    }

    [Fact]
    public void Prune_RemovesExpiredConnections()
    {
        var tracker = new ConnectionHistoryTracker(retention: TimeSpan.FromMinutes(1));
        var start = DateTime.UtcNow;
        tracker.Observe(Connection(1, "a", "b"), start);

        tracker.Prune(start.AddMinutes(2));

        Assert.Equal(0, tracker.Count);
    }

    private static ConnectionInfo Connection(int pid, string local, string remote) => new()
    {
        Pid = pid,
        Protocol = "TCP",
        AddressFamily = "IPv4",
        LocalEndpoint = local,
        RemoteEndpoint = remote
    };
}
