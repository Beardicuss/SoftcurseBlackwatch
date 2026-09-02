using System.Collections.Concurrent;

namespace Softcurse.Shared.Security;

public sealed class CommandRateLimiter
{
    private readonly ConcurrentDictionary<string, DateTime> _nextAllowedUtc = new(StringComparer.Ordinal);
    private readonly Func<DateTime> _utcNow;

    public CommandRateLimiter(Func<DateTime>? utcNow = null) => _utcNow = utcNow ?? (() => DateTime.UtcNow);

    public bool TryAcquire(string key, TimeSpan cooldown)
    {
        if (string.IsNullOrWhiteSpace(key)) throw new ArgumentException("Rate-limit key is required.", nameof(key));
        if (cooldown <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(cooldown));
        var now = _utcNow();
        while (true)
        {
            if (!_nextAllowedUtc.TryGetValue(key, out var nextAllowed))
            {
                if (_nextAllowedUtc.TryAdd(key, now + cooldown))
                {
                    Prune(now);
                    return true;
                }
                continue;
            }
            if (nextAllowed > now) return false;
            if (_nextAllowedUtc.TryUpdate(key, now + cooldown, nextAllowed))
            {
                Prune(now);
                return true;
            }
        }
    }

    private void Prune(DateTime now)
    {
        if (_nextAllowedUtc.Count < 256) return;
        foreach (var expired in _nextAllowedUtc.Where(item => item.Value <= now).Select(item => item.Key).ToList())
            _nextAllowedUtc.TryRemove(expired, out _);
    }
}
