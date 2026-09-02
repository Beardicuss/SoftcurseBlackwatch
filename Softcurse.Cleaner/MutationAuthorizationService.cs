using System.Collections.Concurrent;
using System.Security.Cryptography;
namespace Softcurse.Cleaner;

/// <summary>Issues short-lived, target-bound, single-use capabilities after explicit user consent.</summary>
public sealed class MutationAuthorizationService
{
    private readonly ConcurrentDictionary<string, AuthorizationGrant> _grants = new(StringComparer.Ordinal);
    private readonly TimeSpan _lifetime;

    public MutationAuthorizationService(TimeSpan? lifetime = null)
    {
        _lifetime = lifetime ?? TimeSpan.FromSeconds(30);
        if (_lifetime <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lifetime));
    }

    public MutationAuthorization Issue(MutationAuthorizationScope scope, string targetIdentity, DateTime utcNow)
    {
        if (string.IsNullOrWhiteSpace(targetIdentity)) throw new ArgumentException("Target identity is required.", nameof(targetIdentity));
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        _grants[token] = new AuthorizationGrant(scope, targetIdentity, utcNow + _lifetime);
        Prune(utcNow);
        return new MutationAuthorization(token);
    }

    public bool Consume(MutationAuthorization? authorization, MutationAuthorizationScope scope, string targetIdentity, DateTime utcNow)
    {
        if (authorization is null || !_grants.TryRemove(authorization.Token, out var grant)) return false;
        return grant.ExpiresUtc >= utcNow && grant.Scope == scope && grant.TargetIdentity.Equals(targetIdentity, StringComparison.Ordinal);
    }

    private void Prune(DateTime utcNow)
    {
        foreach (var expired in _grants.Where(pair => pair.Value.ExpiresUtc < utcNow).Select(pair => pair.Key).ToList())
            _grants.TryRemove(expired, out _);
    }

    private sealed record AuthorizationGrant(MutationAuthorizationScope Scope, string TargetIdentity, DateTime ExpiresUtc);
}

public sealed record MutationAuthorization(string Token);

public enum MutationAuthorizationScope
{
    ProcessKill,
    RecoveryRestore,
    RecoveryFinalize,
    RecoveryDismiss
}

public enum RecoveryActionKind
{
    Restore,
    Finalize,
    Dismiss
}
