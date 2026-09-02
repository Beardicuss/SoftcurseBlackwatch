using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Softcurse.Monitor;
using Xunit;

namespace Softcurse.Tests;

public class SignedReputationSetTests
{
    private static readonly DateTime Now = new(2026, 8, 31, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Load_AcceptsAuthenticUnexpiredBundle()
    {
        using var rsa = RSA.Create(2048);
        var payload = Payload("2026.9.1", Now.AddHours(1));
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var set = new SignedReputationSetLoader().Load(payload, signature, rsa.ExportSubjectPublicKeyInfoPem(), Now, "2026.8.1");

        Assert.Equal("2026.9.1", set.FeedVersion);
        Assert.True(set.Match(new string('a', 64), IPAddress.Loopback, string.Empty).Matched);
    }

    [Fact]
    public void Load_RejectsTamperedBundle()
    {
        using var rsa = RSA.Create(2048);
        var payload = Payload("2026.9.1", Now.AddHours(1));
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        payload[^2] ^= 1;
        Assert.Throws<InvalidDataException>(() => new SignedReputationSetLoader().Load(payload, signature, rsa.ExportSubjectPublicKeyInfoPem(), Now));
    }

    [Fact]
    public void Load_RejectsExpiredAndRollbackBundles()
    {
        using var rsa = RSA.Create(2048);
        var expired = Payload("2026.9.1", Now.AddMinutes(-1));
        var expiredSignature = rsa.SignData(expired, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.Throws<InvalidDataException>(() => new SignedReputationSetLoader().Load(expired, expiredSignature, rsa.ExportSubjectPublicKeyInfoPem(), Now));

        var rollback = Payload("2026.7.1", Now.AddHours(1));
        var rollbackSignature = rsa.SignData(rollback, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Assert.Throws<InvalidDataException>(() => new SignedReputationSetLoader().Load(rollback, rollbackSignature, rsa.ExportSubjectPublicKeyInfoPem(), Now, "2026.8.1"));
    }

    [Fact]
    public void Match_UsesExactHostnameNotSuffix()
    {
        var set = Create("2026.9.1", Now.AddHours(1));
        Assert.True(set.Match(string.Empty, IPAddress.Loopback, "bad.example").Matched);
        Assert.False(set.Match(string.Empty, IPAddress.Loopback, "notbad.example").Matched);
    }

    private static byte[] Payload(string version, DateTime expires) => JsonSerializer.SerializeToUtf8Bytes(Create(version, expires));
    private static NetworkReputationSet Create(string version, DateTime expires) => new()
    {
        SchemaVersion = "1.0",
        FeedVersion = version,
        Source = "Blackwatch Test Feed",
        IssuedUtc = Now.AddHours(-1),
        ExpiresUtc = expires,
        MaliciousSha256 = [new string('a', 64)],
        MaliciousIpAddresses = ["203.0.113.25"],
        MaliciousHostNames = ["bad.example"]
    };
}
