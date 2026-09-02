using System.Net;

namespace Softcurse.Monitor;

public sealed class NetworkReputationSet
{
    public string SchemaVersion { get; init; } = "1.0";
    public string FeedVersion { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public DateTime IssuedUtc { get; init; }
    public DateTime ExpiresUtc { get; init; }
    public List<string> MaliciousSha256 { get; init; } = [];
    public List<string> MaliciousIpAddresses { get; init; } = [];
    public List<string> MaliciousHostNames { get; init; } = [];

    public void Validate(DateTime utcNow)
    {
        if (SchemaVersion != "1.0") throw new InvalidDataException($"Unsupported reputation schema '{SchemaVersion}'.");
        if (string.IsNullOrWhiteSpace(FeedVersion) || FeedVersion.Split('.').Any(part => !int.TryParse(part, out _)))
            throw new InvalidDataException("A numeric reputation feed version is required.");
        if (string.IsNullOrWhiteSpace(Source)) throw new InvalidDataException("Reputation feed source is required.");
        if (IssuedUtc == default || ExpiresUtc <= IssuedUtc || ExpiresUtc <= utcNow)
            throw new InvalidDataException("Reputation feed is expired or has an invalid validity window.");
        if (MaliciousSha256.Any(hash => hash.Length != 64 || hash.Any(character => !Uri.IsHexDigit(character))))
            throw new InvalidDataException("Reputation feed contains an invalid SHA-256 indicator.");
        if (MaliciousIpAddresses.Any(value => !IPAddress.TryParse(value, out _)))
            throw new InvalidDataException("Reputation feed contains an invalid IP indicator.");
        if (MaliciousHostNames.Any(host => string.IsNullOrWhiteSpace(host) || host.Contains('/') || host.Contains(':')))
            throw new InvalidDataException("Reputation feed contains an invalid hostname indicator.");
    }

    public ReputationMatch Match(string sha256, IPAddress address, string hostName)
    {
        if (!string.IsNullOrWhiteSpace(sha256) && MaliciousSha256.Contains(sha256, StringComparer.OrdinalIgnoreCase))
            return new(true, "reputation.malicious-sha256", sha256, Source, FeedVersion);
        var addressText = address.ToString();
        if (MaliciousIpAddresses.Contains(addressText, StringComparer.OrdinalIgnoreCase))
            return new(true, "reputation.malicious-ip", addressText, Source, FeedVersion);
        var normalizedHost = hostName.Trim().TrimEnd('.');
        if (!string.IsNullOrEmpty(normalizedHost) && MaliciousHostNames.Any(host => normalizedHost.Equals(host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)))
            return new(true, "reputation.malicious-hostname", normalizedHost, Source, FeedVersion);
        return ReputationMatch.None;
    }
}

public sealed record ReputationMatch(bool Matched, string RuleId, string Value, string Source, string FeedVersion)
{
    public static ReputationMatch None { get; } = new(false, string.Empty, string.Empty, string.Empty, string.Empty);
}
