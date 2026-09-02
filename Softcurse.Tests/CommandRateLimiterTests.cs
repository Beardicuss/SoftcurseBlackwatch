using Softcurse.Shared.Security;
using Xunit;

namespace Softcurse.Tests;

public sealed class CommandRateLimiterTests
{
    [Fact]
    public void TryAcquire_RejectsRepeatedKeyUntilCooldownExpires()
    {
        var now = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);
        var limiter = new CommandRateLimiter(() => now);

        Assert.True(limiter.TryAcquire("recovery:one", TimeSpan.FromSeconds(30)));
        Assert.False(limiter.TryAcquire("recovery:one", TimeSpan.FromSeconds(30)));
        now = now.AddSeconds(30);
        Assert.True(limiter.TryAcquire("recovery:one", TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public void TryAcquire_IsolatesTargets()
    {
        var limiter = new CommandRateLimiter(() => DateTime.UtcNow);

        Assert.True(limiter.TryAcquire("kill:41", TimeSpan.FromSeconds(10)));
        Assert.True(limiter.TryAcquire("kill:42", TimeSpan.FromSeconds(10)));
        Assert.False(limiter.TryAcquire("kill:41", TimeSpan.FromSeconds(10)));
    }
}
