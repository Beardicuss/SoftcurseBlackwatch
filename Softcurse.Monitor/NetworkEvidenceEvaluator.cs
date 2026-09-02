using System.Net;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

public static class NetworkEvidenceEvaluator
{
    private static readonly HashSet<int> MiningPorts =
    [
        3333, 4444, 5555, 7777, 8888, 9999, 14444, 14433,
        20535, 20536, 45560, 45700, 3334, 5556, 8899
    ];

    private static readonly string[] MinerProcessPatterns =
    [
        "xmrig", "cpuminer", "minerd", "cgminer", "bfgminer", "nbminer",
        "phoenixminer", "gminer", "lolminer", "ethminer", "nicehash"
    ];

    public static NetworkAssessment Evaluate(
        string processName,
        IPAddress remoteAddress,
        int remotePort,
        ProcessInfo? process = null,
        string remoteHostName = "",
        NetworkReputationSet? reputation = null)
    {
        var evidence = new List<NetworkEvidence>();
        var miningPort = MiningPorts.Contains(remotePort);
        var minerIdentity = MinerProcessPatterns.Any(pattern =>
            processName.Contains(pattern, StringComparison.OrdinalIgnoreCase));

        if (miningPort)
            evidence.Add(new NetworkEvidence
            {
                RuleId = "network.mining-associated-port",
                Description = "Remote port is commonly used by mining pools but is not malicious by itself.",
                ObservedValue = remotePort.ToString(),
                Confidence = DetectionConfidence.Low
            });
        if (minerIdentity)
            evidence.Add(new NetworkEvidence
            {
                RuleId = "network.miner-process-identity",
                Description = "Owning process name matches a known miner family.",
                ObservedValue = processName,
                Confidence = DetectionConfidence.Medium
            });

        var processSignal = process?.Score.Signals
            .OrderByDescending(signal => signal.Confidence)
            .ThenByDescending(signal => signal.Weight)
            .FirstOrDefault();
        if (process is not null && process.Score.Level >= ThreatLevel.Suspicious && processSignal is not null)
            evidence.Add(new NetworkEvidence
            {
                RuleId = "network.process-evidence-correlation",
                Description = "The owning process has independently reviewable detection evidence.",
                ObservedValue = $"{process.Score.Level}/{process.Score.Confidence}: {processSignal.Name}",
                Confidence = process.Score.Confidence,
                SourceEvidenceId = processSignal.EvidenceId
            });

        var reputationMatch = reputation?.Match(process?.FileHash ?? string.Empty, remoteAddress, remoteHostName) ?? ReputationMatch.None;
        if (reputationMatch.Matched)
            evidence.Add(new NetworkEvidence
            {
                RuleId = reputationMatch.RuleId,
                Description = $"Exact match in authenticated reputation feed '{reputationMatch.Source}' version {reputationMatch.FeedVersion}.",
                ObservedValue = reputationMatch.Value,
                Confidence = DetectionConfidence.High
            });

        var processCorroboration = minerIdentity || process?.Score.Signals.Any(signal =>
            signal.Name.Contains("miner", StringComparison.OrdinalIgnoreCase) ||
            signal.Category == SignalCategory.CommandLine && signal.Confidence == DetectionConfidence.High) == true;
        var corroborated = miningPort && processCorroboration && !IsLocalOrPrivate(remoteAddress);
        var suspicious = reputationMatch.Matched || corroborated;
        var overallConfidence = reputationMatch.Matched
            ? DetectionConfidence.High
            : corroborated && process?.Score.Confidence == DetectionConfidence.High
            ? DetectionConfidence.High
            : corroborated ? DetectionConfidence.Medium
            : evidence.Count > 0 ? evidence.Max(item => item.Confidence) : DetectionConfidence.None;
        return new NetworkAssessment(
            suspicious,
            overallConfidence,
            evidence,
            reputationMatch.Matched
                ? $"Authenticated reputation match from {reputationMatch.Source} ({reputationMatch.FeedVersion})."
                : corroborated
                ? "Mining-associated port corroborated by miner process identity and a public remote endpoint."
                : evidence.Count > 0 ? "Context recorded; insufficient corroboration for an alert." : string.Empty);
    }

    private static bool IsLocalOrPrivate(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return true;
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 16)
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (bytes[0] & 0xfe) == 0xfc;
        return bytes.Length == 4 && (bytes[0] == 10 ||
                (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
                (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 169 && bytes[1] == 254));
    }
}

public sealed record NetworkAssessment(
    bool IsSuspicious,
    DetectionConfidence Confidence,
    IReadOnlyList<NetworkEvidence> Evidence,
    string Reason);
