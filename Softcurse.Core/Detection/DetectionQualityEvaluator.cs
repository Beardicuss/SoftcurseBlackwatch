using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

/// <summary>Evaluates labeled fixtures and reports false-positive/false-negative quality metrics.</summary>
public static class DetectionQualityEvaluator
{
    public static DetectionQualityReport Evaluate(
        IEnumerable<LabeledProcessFixture> fixtures,
        Func<ProcessInfo, ThreatScore> score,
        ThreatLevel alertThreshold = ThreatLevel.Suspicious)
    {
        var results = fixtures.Select(fixture =>
        {
            var threatScore = score(fixture.Process);
            return new FixtureEvaluation(
                fixture.Id,
                fixture.IsMalicious,
                threatScore.Level >= alertThreshold,
                threatScore.Total,
                threatScore.Explanation);
        }).ToList();

        return new DetectionQualityReport(results);
    }
}

public sealed record LabeledProcessFixture(string Id, bool IsMalicious, ProcessInfo Process);
public sealed record FixtureEvaluation(string Id, bool ExpectedMalicious, bool Alerted, int Score, string Explanation);

public sealed class DetectionQualityReport(IReadOnlyList<FixtureEvaluation> results)
{
    public IReadOnlyList<FixtureEvaluation> Results { get; } = results;
    public int TruePositives => Results.Count(r => r.ExpectedMalicious && r.Alerted);
    public int TrueNegatives => Results.Count(r => !r.ExpectedMalicious && !r.Alerted);
    public int FalsePositives => Results.Count(r => !r.ExpectedMalicious && r.Alerted);
    public int FalseNegatives => Results.Count(r => r.ExpectedMalicious && !r.Alerted);
    public double Precision => Divide(TruePositives, TruePositives + FalsePositives);
    public double Recall => Divide(TruePositives, TruePositives + FalseNegatives);
    public double FalsePositiveRate => Divide(FalsePositives, FalsePositives + TrueNegatives);
    private static double Divide(int numerator, int denominator) => denominator == 0 ? 0 : (double)numerator / denominator;
}

public sealed record DetectionQualityThresholds(
    double MinimumPrecision,
    double MinimumRecall,
    double MaximumFalsePositiveRate)
{
    public static DetectionQualityThresholds ReleaseBaseline { get; } = new(0.95, 0.90, 0.01);

    public void Enforce(DetectionQualityReport report)
    {
        var failures = new List<string>();
        if (report.Precision < MinimumPrecision)
            failures.Add($"precision {report.Precision:P2} is below {MinimumPrecision:P2}");
        if (report.Recall < MinimumRecall)
            failures.Add($"recall {report.Recall:P2} is below {MinimumRecall:P2}");
        if (report.FalsePositiveRate > MaximumFalsePositiveRate)
            failures.Add($"false-positive rate {report.FalsePositiveRate:P2} exceeds {MaximumFalsePositiveRate:P2}");
        if (failures.Count > 0)
            throw new InvalidDataException("Detection quality gate failed: " + string.Join("; ", failures));
    }
}
