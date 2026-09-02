using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

public sealed class DetectionRuleSet
{
    public string SchemaVersion { get; init; } = "1.0";
    public string RuleSetVersion { get; init; } = "2026.08.31.1";
    public IReadOnlyDictionary<string, DetectionRule> Rules { get; init; } = DefaultRules();

    public DetectionRule Get(string id) => Rules.TryGetValue(id, out var rule)
        ? rule
        : throw new InvalidDataException($"Detection rule '{id}' is not defined.");

    public void Validate()
    {
        if (SchemaVersion != "1.0")
            throw new InvalidDataException($"Unsupported detection schema '{SchemaVersion}'.");
        if (string.IsNullOrWhiteSpace(RuleSetVersion) || Rules.Count == 0)
            throw new InvalidDataException("A versioned, non-empty rule set is required.");
        foreach (var (id, rule) in Rules)
        {
            if (id != rule.Id || rule.Weight is < 1 or > 100)
                throw new InvalidDataException($"Detection rule '{id}' is invalid.");
        }
    }

    private static IReadOnlyDictionary<string, DetectionRule> DefaultRules()
    {
        DetectionRule[] rules =
        [
            new("process.known-miner-name", "Known miner name", 50, SignalCategory.ProcessName, DetectionConfidence.Medium),
            new("command.mining", "Mining command line", 40, SignalCategory.CommandLine, DetectionConfidence.High),
            new("path.user-writable", "User-writable execution path", 15, SignalCategory.FilePath, DetectionConfidence.Low),
            new("process.path-unavailable", "Executable path unavailable", 5, SignalCategory.Signature, DetectionConfidence.Low),
            new("behavior.background-high-cpu", "Background high CPU", 20, SignalCategory.CpuBehavior, DetectionConfidence.Low),
            new("behavior.sustained-high-cpu", "Sustained high CPU", 25, SignalCategory.CpuBehavior, DetectionConfidence.Medium),
            new("process.suspicious-parent", "Suspicious parent chain", 20, SignalCategory.ParentChain, DetectionConfidence.Low),
            new("process.system-name-impersonation", "System name impersonation", 35, SignalCategory.ProcessName, DetectionConfidence.Medium),
            new("behavior.high-memory", "High memory use", 5, SignalCategory.CpuBehavior, DetectionConfidence.Low),
            new("file.unsigned-user-writable", "Unsigned binary in user-writable path", 15, SignalCategory.Signature, DetectionConfidence.Medium),
            new("process.known-rat-name", "Known RAT name", 45, SignalCategory.ProcessName, DetectionConfidence.Medium),
            new("command.malicious", "Malicious command pattern", 55, SignalCategory.CommandLine, DetectionConfidence.High),
        ];
        return rules.ToDictionary(r => r.Id, StringComparer.Ordinal);
    }
}

public sealed record DetectionRule(
    string Id,
    string DisplayName,
    int Weight,
    SignalCategory Category,
    DetectionConfidence Confidence);
