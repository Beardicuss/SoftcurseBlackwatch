using Softcurse.Cleaner;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class MutationAuthorizationServiceTests
{
    private static readonly DateTime Now = new(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Consume_AcceptsMatchingGrantExactlyOnce()
    {
        var service = new MutationAuthorizationService(TimeSpan.FromSeconds(30));
        var grant = service.Issue(MutationAuthorizationScope.ProcessKill, "pid:42|name:sample", Now);

        Assert.True(service.Consume(grant, MutationAuthorizationScope.ProcessKill, "pid:42|name:sample", Now.AddSeconds(1)));
        Assert.False(service.Consume(grant, MutationAuthorizationScope.ProcessKill, "pid:42|name:sample", Now.AddSeconds(2)));
    }

    [Fact]
    public void Consume_RejectsAndConsumesWrongTargetGrant()
    {
        var service = new MutationAuthorizationService();
        var grant = service.Issue(MutationAuthorizationScope.ProcessKill, "pid:42", Now);

        Assert.False(service.Consume(grant, MutationAuthorizationScope.ProcessKill, "pid:43", Now));
        Assert.False(service.Consume(grant, MutationAuthorizationScope.ProcessKill, "pid:42", Now));
    }

    [Fact]
    public void Consume_RejectsExpiredGrant()
    {
        var service = new MutationAuthorizationService(TimeSpan.FromSeconds(5));
        var grant = service.Issue(MutationAuthorizationScope.ProcessKill, "pid:42", Now);

        Assert.False(service.Consume(grant, MutationAuthorizationScope.ProcessKill, "pid:42", Now.AddSeconds(6)));
    }

    [Fact]
    public void Consume_RejectsWrongActionType()
    {
        var service = new MutationAuthorizationService();
        var grant = service.Issue(MutationAuthorizationScope.ProcessKill, "pid:42", Now);

        Assert.False(service.Consume(grant, MutationAuthorizationScope.RecoveryRestore, "pid:42", Now));
    }
}
