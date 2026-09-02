using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace Softcurse.Monitor;

/// <summary>Bounded reverse-DNS cache with request deduplication, negative caching, and timeouts.</summary>
public sealed class ReverseDnsCache : IDisposable
{
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, Task<string>> _inflight = new(StringComparer.Ordinal);
    private readonly Func<IPAddress, CancellationToken, Task<string?>> _resolver;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly TimeSpan _timeout;
    private readonly TimeSpan _ttl;
    private readonly int _capacity;

    public ReverseDnsCache(
        Func<IPAddress, CancellationToken, Task<string?>>? resolver = null,
        TimeSpan? timeout = null,
        TimeSpan? ttl = null,
        int capacity = 4096)
    {
        _resolver = resolver ?? ResolveSystemAsync;
        _timeout = timeout ?? TimeSpan.FromMilliseconds(750);
        _ttl = ttl ?? TimeSpan.FromMinutes(15);
        _capacity = capacity > 0 ? capacity : throw new ArgumentOutOfRangeException(nameof(capacity));
        if (_timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        if (_ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));
    }

    public string GetCachedOrQueue(IPAddress address)
    {
        var key = address.ToString();
        if (_cache.TryGetValue(key, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
            return cached.HostName;
        _ = QueueAsync(address);
        return string.Empty;
    }

    private async Task QueueAsync(IPAddress address)
    {
        try { await ResolveAsync(address, _lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
    }

    public async Task<string> ResolveAsync(IPAddress address, CancellationToken cancellationToken = default)
    {
        var key = address.ToString();
        if (_cache.TryGetValue(key, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
            return cached.HostName;

        var task = _inflight.GetOrAdd(key, _ => ResolveCoreAsync(address));
        try { return await task.WaitAsync(cancellationToken).ConfigureAwait(false); }
        finally { _inflight.TryRemove(key, out _); }
    }

    private async Task<string> ResolveCoreAsync(IPAddress address)
    {
        string hostName;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            timeout.CancelAfter(_timeout);
            hostName = (await _resolver(address, timeout.Token).ConfigureAwait(false))?.Trim() ?? string.Empty;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            hostName = string.Empty;
        }

        if (_cache.Count >= _capacity)
        {
            var oldest = _cache.MinBy(pair => pair.Value.ExpiresUtc).Key;
            _cache.TryRemove(oldest, out _);
        }
        _cache[address.ToString()] = new CacheEntry(hostName, DateTime.UtcNow + _ttl);
        return hostName;
    }

    private static async Task<string?> ResolveSystemAsync(IPAddress address, CancellationToken cancellationToken)
    {
        var entry = await Dns.GetHostEntryAsync(address).WaitAsync(cancellationToken).ConfigureAwait(false);
        return entry.HostName;
    }

    public void Dispose()
    {
        _lifetime.Cancel();
        _lifetime.Dispose();
    }

    private sealed record CacheEntry(string HostName, DateTime ExpiresUtc);
}
