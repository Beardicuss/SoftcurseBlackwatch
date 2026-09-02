using System.Security.Cryptography;
using System.Text.Json;

namespace Softcurse.Monitor;

public sealed class SignedReputationSetLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = false };

    public NetworkReputationSet Load(
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature,
        string publicKeyPem,
        DateTime utcNow,
        string? minimumAcceptedVersion = null)
    {
        using var rsa = RSA.Create();
        try { rsa.ImportFromPem(publicKeyPem); }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new InvalidDataException("The reputation-signing public key is invalid.", ex);
        }
        if (!rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Reputation bundle signature verification failed.");

        NetworkReputationSet set;
        try { set = JsonSerializer.Deserialize<NetworkReputationSet>(payload, JsonOptions) ?? throw new InvalidDataException("Reputation bundle is empty."); }
        catch (JsonException ex) { throw new InvalidDataException("Reputation bundle JSON is invalid.", ex); }
        set.Validate(utcNow);
        if (minimumAcceptedVersion is not null && CompareVersions(set.FeedVersion, minimumAcceptedVersion) < 0)
            throw new InvalidDataException($"Reputation bundle rollback rejected: {set.FeedVersion} < {minimumAcceptedVersion}.");
        return set;
    }

    private static int CompareVersions(string left, string right)
    {
        static int[] Parse(string value)
        {
            var parts = value.Split('.');
            if (parts.Any(part => !int.TryParse(part, out _))) throw new InvalidDataException($"Version '{value}' is not numeric.");
            return parts.Select(int.Parse).ToArray();
        }
        var a = Parse(left); var b = Parse(right);
        for (var index = 0; index < Math.Max(a.Length, b.Length); index++)
        {
            var comparison = (index < a.Length ? a[index] : 0).CompareTo(index < b.Length ? b[index] : 0);
            if (comparison != 0) return comparison;
        }
        return 0;
    }
}
