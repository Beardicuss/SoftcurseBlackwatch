using Softcurse.Core.Detection;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using System.Text.Json;
using Xunit;

namespace Softcurse.Tests;

public sealed class DetectionQualityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-quality-{Guid.NewGuid():N}");

    [Fact]
    public void BaselineCorpus_HasNoFalsePositivesOrMisses()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var scorer = new ThreatScorer(logger, new BlackwatchConfig());
        var corpusPath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "process-corpus.json");
        var fixtures = JsonSerializer.Deserialize<List<LabeledProcessFixture>>(
            File.ReadAllText(corpusPath),
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        Assert.Equal(12, fixtures.Count);

        var report = DetectionQualityEvaluator.Evaluate(fixtures, process => scorer.Score(process).Score);

        Assert.Equal(6, report.TruePositives);
        Assert.Equal(6, report.TrueNegatives);
        Assert.Equal(0, report.FalsePositives);
        Assert.Equal(0, report.FalseNegatives);
        Assert.Equal(1, report.Precision);
        Assert.Equal(1, report.Recall);
        DetectionQualityThresholds.ReleaseBaseline.Enforce(report);
    }

    [Fact]
    public void ReleaseGate_RejectsFalsePositiveRegression()
    {
        var report = new DetectionQualityReport(
        [
            new FixtureEvaluation("benign", false, true, 55, "incorrect alert"),
            new FixtureEvaluation("malicious", true, true, 90, "correct alert")
        ]);

        var error = Assert.Throws<InvalidDataException>(() =>
            DetectionQualityThresholds.ReleaseBaseline.Enforce(report));
        Assert.Contains("false-positive", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
