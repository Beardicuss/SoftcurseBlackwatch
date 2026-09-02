using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

/// <summary>Loads an external rule bundle only after detached RSA-PSS/SHA-256 verification.</summary>
public sealed class SignedRuleSetLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        Converters = { new JsonStringEnumConverter() }
    };

    public DetectionRuleSet Load(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        string publicKeyPem,
        string? minimumAcceptedVersion = null)
    {
        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(publicKeyPem);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new InvalidDataException("The rule-signing public key is invalid.", ex);
        }

        if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Rule bundle signature verification failed.");

        RuleBundleDocument document;
        try
        {
            document = JsonSerializer.Deserialize<RuleBundleDocument>(payload, JsonOptions)
                ?? throw new InvalidDataException("Rule bundle is empty.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Rule bundle JSON is invalid.", ex);
        }

        if (minimumAcceptedVersion is not null &&
            CompareVersions(document.RuleSetVersion, minimumAcceptedVersion) < 0)
            throw new InvalidDataException($"Rule bundle rollback rejected: {document.RuleSetVersion} < {minimumAcceptedVersion}.");

        IReadOnlyDictionary<string, DetectionRule> rules;
        try
        {
            rules = document.Rules.ToDictionary(rule => rule.Id, StringComparer.Ordinal);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidDataException("Rule bundle contains duplicate rule identifiers.", ex);
        }

        var ruleSet = new DetectionRuleSet
        {
            SchemaVersion = document.SchemaVersion,
            RuleSetVersion = document.RuleSetVersion,
            Rules = rules
        };
        ruleSet.Validate();
        return ruleSet;
    }

    public DetectionRuleSet LoadFiles(
        string payloadPath,
        string signaturePath,
        string publicKeyPem,
        string? minimumAcceptedVersion = null) =>
        Load(File.ReadAllBytes(payloadPath), File.ReadAllBytes(signaturePath), publicKeyPem, minimumAcceptedVersion);

    internal static int CompareVersions(string left, string right)
    {
        var leftParts = ParseVersion(left);
        var rightParts = ParseVersion(right);
        for (var index = 0; index < Math.Max(leftParts.Length, rightParts.Length); index++)
        {
            var leftPart = index < leftParts.Length ? leftParts[index] : 0;
            var rightPart = index < rightParts.Length ? rightParts[index] : 0;
            var comparison = leftPart.CompareTo(rightPart);
            if (comparison != 0) return comparison;
        }
        return 0;
    }

    private static int[] ParseVersion(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidDataException("Rule-set version is required.");
        var parts = value.Split('.');
        if (parts.Any(part => !int.TryParse(part, out _)))
            throw new InvalidDataException($"Rule-set version '{value}' is not numeric.");
        return parts.Select(int.Parse).ToArray();
    }
}

public sealed class RuleBundleDocument
{
    public string SchemaVersion { get; init; } = string.Empty;
    public string RuleSetVersion { get; init; } = string.Empty;
    public List<DetectionRule> Rules { get; init; } = [];
}
