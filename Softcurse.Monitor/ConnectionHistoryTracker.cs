using System.Security.Cryptography;
using System.Text;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>Maintains bounded, expiring connection history across network snapshots.</summary>
public sealed class ConnectionHistoryTracker
{
    private readonly Dictionary<string, HistoryEntry> _entries = new(StringComparer.Ordinal);
    private readonly int _capacity;
    private readonly TimeSpan _retention;

    public ConnectionHistoryTracker(int capacity = 10_000, TimeSpan? retention = null)
    {
        if (capacity < 1) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _retention = retention ?? TimeSpan.FromMinutes(30);
        if (_retention <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(retention));
    }

    public int Count => _entries.Count;

    public void Observe(ConnectionInfo connection, DateTime utcNow)
    {
        var id = CreateId(connection);
        Prune(utcNow);
        if (!_entries.TryGetValue(id, out var entry))
        {
            if (_entries.Count >= _capacity)
            {
                var oldest = _entries.MinBy(pair => pair.Value.LastSeenUtc).Key;
                _entries.Remove(oldest);
            }
            entry = new HistoryEntry(utcNow, utcNow, 0);
        }

        entry = entry with { LastSeenUtc = utcNow, ObservationCount = entry.ObservationCount + 1 };
        _entries[id] = entry;
        connection.ConnectionId = id;
        connection.FirstSeenUtc = entry.FirstSeenUtc;
        connection.LastSeenUtc = entry.LastSeenUtc;
        connection.ObservationCount = entry.ObservationCount;
    }

    public void Prune(DateTime utcNow)
    {
        var cutoff = utcNow - _retention;
        foreach (var stale in _entries.Where(pair => pair.Value.LastSeenUtc < cutoff).Select(pair => pair.Key).ToList())
            _entries.Remove(stale);
    }

    private static string CreateId(ConnectionInfo connection)
    {
        var canonical = $"{connection.Protocol}|{connection.AddressFamily}|{connection.Pid}|{connection.LocalEndpoint}|{connection.RemoteEndpoint}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private sealed record HistoryEntry(DateTime FirstSeenUtc, DateTime LastSeenUtc, int ObservationCount);
}
