using Softcurse.Core.Detection;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class DetectionPipelineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-detection-{Guid.NewGuid():N}");

    [Fact]
    public void Score_ProducesVersionedExplainableEvidence()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var process = new ProcessInfo
        {
            Pid = 123,
            StartTime = DateTime.UtcNow,
            Name = "xmrig",
            FilePath = @"C:\Users\Public\xmrig.exe",
            CommandLine = "xmrig --stratum stratum+tcp://pool.example",
            IsSigned = false
        };

        new ThreatScorer(logger).Score(process);

        Assert.True(process.Score.Level >= ThreatLevel.High);
        Assert.Equal(DetectionConfidence.High, process.Score.Confidence);
        Assert.NotEmpty(process.Score.RuleSetVersion);
        Assert.All(process.Score.Signals, signal =>
        {
            Assert.NotEmpty(signal.EvidenceId);
            Assert.NotEmpty(signal.ObservedValue);
            Assert.NotEmpty(signal.RuleVersion);
        });
        Assert.DoesNotContain("AUTO", process.Score.RecommendedAction);
    }

    [Fact]
    public void Score_DoesNotTreatLegacyWhitelistAsPathSubstring()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var config = new BlackwatchConfig { Whitelist = ["trusted"] };
        var process = new ProcessInfo
        {
            Pid = 123,
            StartTime = DateTime.UtcNow,
            Name = "xmrig",
            FilePath = @"C:\trusted\xmrig.exe"
        };

        new ThreatScorer(logger, config).Score(process);

        Assert.NotEmpty(process.Score.Signals);
    }

    [Fact]
    public void Score_TrustsMatchingPathHashAndPublisherIdentity()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var config = new BlackwatchConfig
        {
            TrustedApplications =
            [
                new TrustedApplication
                {
                    TrustId = "fixture",
                    Name = "xmrig",
                    Sha256 = new string('a', 64),
                    CanonicalPath = @"C:\Temp\xmrig.exe",
                    PublisherThumbprint = "publisher",
                    Reason = "test fixture"
                }
            ]
        };
        var process = new ProcessInfo
        {
            Name = "xmrig",
            FileHash = new string('A', 64),
            FilePath = @"C:\Temp\xmrig.exe",
            PublisherThumbprint = "PUBLISHER"
        };

        new ThreatScorer(logger, config).Score(process);

        Assert.Empty(process.Score.Signals);
        Assert.Contains("trusted", process.Score.Explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@"C:\Other\xmrig.exe", false, "publisher")]
    [InlineData(@"C:\Temp\xmrig.exe", false, "different-publisher")]
    public void Score_RejectsTrustedIdentityWhenAnyBindingDiffers(string path, bool matchingHash, string publisher)
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var config = new BlackwatchConfig
        {
            TrustedApplications =
            [
                new TrustedApplication
                {
                    TrustId = "fixture",
                    Name = "xmrig",
                    Sha256 = new string('a', 64),
                    CanonicalPath = @"C:\Temp\xmrig.exe",
                    PublisherThumbprint = "publisher"
                }
            ]
        };
        var process = new ProcessInfo
        {
            Name = "xmrig",
            FileHash = new string(matchingHash ? 'a' : 'b', 64),
            FilePath = path,
            PublisherThumbprint = publisher
        };

        new ThreatScorer(logger, config).Score(process);

        Assert.NotEmpty(process.Score.Signals);
    }

    [Fact]
    public void Score_DoesNotApplyExactLegacyNameWhitelist()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var config = new BlackwatchConfig { Whitelist = ["xmrig"] };
        var process = new ProcessInfo { Name = "xmrig", FilePath = @"C:\Temp\xmrig.exe" };

        new ThreatScorer(logger, config).Score(process);

        Assert.NotEmpty(process.Score.Signals);
    }

    [Fact]
    public void RuleSet_RejectsUnsupportedSchema()
    {
        var rules = new DetectionRuleSet { SchemaVersion = "2.0" };
        Assert.Throws<InvalidDataException>(rules.Validate);
    }

    [Fact]
    public void Score_ProducesStableEvidenceFingerprints()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var scorer = new ThreatScorer(logger);
        ProcessInfo Fixture() => new()
        {
            Pid = 123,
            StartTime = DateTime.UtcNow,
            Name = "xmrig",
            FilePath = @"C:\Program Files\xmrig.exe"
        };

        var first = scorer.Score(Fixture()).Score.Signals.Single().EvidenceId;
        var second = scorer.Score(Fixture()).Score.Signals.Single().EvidenceId;

        Assert.Equal(first, second);
        Assert.Equal(64, first.Length);
    }

    [Fact]
    public void Score_RequiresOptionalProductMetadataToMatchTrustRule()
    {
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));
        var config = new BlackwatchConfig
        {
            TrustedApplications =
            [
                new TrustedApplication
                {
                    PublisherThumbprint = "thumbprint",
                    ProductName = "Approved Product",
                    CompanyName = "Approved Company",
                    Reason = "publisher-scoped product"
                }
            ]
        };
        var process = new ProcessInfo
        {
            Name = "xmrig",
            PublisherThumbprint = "thumbprint",
            ProductName = "Different Product",
            CompanyName = "Approved Company"
        };

        new ThreatScorer(logger, config).Score(process);

        Assert.NotEmpty(process.Score.Signals);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
