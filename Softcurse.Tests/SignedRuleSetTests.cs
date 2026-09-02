using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Softcurse.Core.Detection;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class SignedRuleSetTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    [Fact]
    public void Load_AcceptsAuthenticVersionedBundle()
    {
        using var rsa = RSA.Create(2048);
        var payload = CreatePayload("2026.09.1");
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var loaded = new SignedRuleSetLoader().Load(payload, signature, rsa.ExportSubjectPublicKeyInfoPem(), "2026.08.31.1");

        Assert.Equal("2026.09.1", loaded.RuleSetVersion);
        Assert.Equal(50, loaded.Get("process.known-miner-name").Weight);
    }

    [Fact]
    public void Load_RejectsPayloadChangedAfterSigning()
    {
        using var rsa = RSA.Create(2048);
        var payload = CreatePayload("2026.09.1");
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        payload[^2] ^= 1;

        var error = Assert.Throws<InvalidDataException>(() =>
            new SignedRuleSetLoader().Load(payload, signature, rsa.ExportSubjectPublicKeyInfoPem()));

        Assert.Contains("signature", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Load_RejectsSignedRollbackBundle()
    {
        using var rsa = RSA.Create(2048);
        var payload = CreatePayload("2026.07.1");
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var error = Assert.Throws<InvalidDataException>(() =>
            new SignedRuleSetLoader().Load(payload, signature, rsa.ExportSubjectPublicKeyInfoPem(), "2026.08.31.1"));

        Assert.Contains("rollback", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] CreatePayload(string version)
    {
        var document = new RuleBundleDocument
        {
            SchemaVersion = "1.0",
            RuleSetVersion = version,
            Rules =
            [
                new DetectionRule("process.known-miner-name", "Known miner name", 50, SignalCategory.ProcessName, DetectionConfidence.Medium)
            ]
        };
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(document, JsonOptions));
    }
}
