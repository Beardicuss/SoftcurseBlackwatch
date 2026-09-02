using System.Net;
using Softcurse.Monitor;
using Xunit;

namespace Softcurse.Tests;

public class ReverseDnsCacheTests
{
    [Fact]
    public async Task ResolveAsync_CachesSuccessfulLookup()
    {
        var calls = 0;
        using var cache = new ReverseDnsCache((_, _) =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult<string?>("example.test");
        });
        var address = IPAddress.Parse("203.0.113.10");

        var first = await cache.ResolveAsync(address);
        var second = await cache.ResolveAsync(address);

        Assert.Equal("example.test", first);
        Assert.Equal(first, second);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ResolveAsync_DeduplicatesConcurrentLookups()
    {
        var calls = 0;
        using var cache = new ReverseDnsCache(async (_, token) =>
        {
            Interlocked.Increment(ref calls);
            await Task.Delay(25, token);
            return "shared.test";
        });
        var address = IPAddress.Parse("203.0.113.11");

        var results = await Task.WhenAll(cache.ResolveAsync(address), cache.ResolveAsync(address));

        Assert.All(results, result => Assert.Equal("shared.test", result));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ResolveAsync_TimesOutAndNegativeCachesFailure()
    {
        var calls = 0;
        using var cache = new ReverseDnsCache(async (_, token) =>
        {
            Interlocked.Increment(ref calls);
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return "unreachable";
        }, timeout: TimeSpan.FromMilliseconds(30));
        var address = IPAddress.Parse("203.0.113.12");

        var first = await cache.ResolveAsync(address);
        var second = await cache.ResolveAsync(address);

        Assert.Empty(first);
        Assert.Empty(second);
        Assert.Equal(1, calls);
    }
}
