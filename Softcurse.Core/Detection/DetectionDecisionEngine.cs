using System.Security.Cryptography;
using System.Text;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

public sealed class DetectionDecisionEngine(DetectionRuleSet ruleSet)
{
    public ThreatScore Decide(IReadOnlyCollection<DetectionObservation> observations)
    {
        var signals = observations.Select(observation =>
        {
            var rule = ruleSet.Get(observation.RuleId);
            return new ThreatSignal
            {
                EvidenceId = CreateEvidenceFingerprint(observation),
                Name = rule.DisplayName,
                Description = observation.Description,
                ObservedValue = observation.ObservedValue,
                Weight = rule.Weight,
                Category = rule.Category,
                Confidence = rule.Confidence,
                RuleVersion = ruleSet.RuleSetVersion
            };
        }).ToList();

        var confidence = signals.Count == 0
            ? DetectionConfidence.None
            : signals.Max(s => s.Confidence);
        var explanation = signals.Count == 0
            ? "No suspicious evidence observed."
            : $"{signals.Count} evidence item(s); strongest confidence is {confidence}. " +
              string.Join(" ", signals.OrderByDescending(s => s.Weight).Take(3).Select(s => s.Description));

        return new ThreatScore
        {
            Signals = signals,
            Confidence = confidence,
            Explanation = explanation,
            RuleSetVersion = ruleSet.RuleSetVersion
        };
    }

    private string CreateEvidenceFingerprint(DetectionObservation observation)
    {
        var canonical = $"{ruleSet.RuleSetVersion}\n{observation.RuleId}\n{observation.ObservedValue}\n{observation.Description}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }
}

public sealed record DetectionObservation(string RuleId, string Description, string ObservedValue);
