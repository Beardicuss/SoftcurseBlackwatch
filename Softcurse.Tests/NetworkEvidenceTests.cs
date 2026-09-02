using System.Net;
using Softcurse.Monitor;
using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public class NetworkEvidenceTests
{
    [Fact]
    public void MiningPortAlone_IsContextNotAlert()
    {
        var result = NetworkEvidenceEvaluator.Evaluate("browser", IPAddress.Parse("203.0.113.10"), 3333);

        Assert.False(result.IsSuspicious);
        Assert.Equal(DetectionConfidence.Low, result.Confidence);
        Assert.Single(result.Evidence);
    }

    [Fact]
    public void MinerIdentityAndPublicMiningPort_AreCorroborated()
    {
        var result = NetworkEvidenceEvaluator.Evaluate("xmrig", IPAddress.Parse("203.0.113.10"), 3333);

        Assert.True(result.IsSuspicious);
        Assert.Equal(DetectionConfidence.Medium, result.Confidence);
        Assert.Equal(2, result.Evidence.Count);
    }

    [Fact]
    public void PrivateEndpoint_DoesNotRaiseCorroboratedAlert()
    {
        var result = NetworkEvidenceEvaluator.Evaluate("xmrig", IPAddress.Parse("192.168.1.10"), 3333);

        Assert.False(result.IsSuspicious);
    }

    [Theory]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    [InlineData("fd00::1")]
    public void LocalOrPrivateIpv6_DoesNotRaiseCorroboratedAlert(string address)
    {
        var result = NetworkEvidenceEvaluator.Evaluate("xmrig", IPAddress.Parse(address), 3333);
        Assert.False(result.IsSuspicious);
    }

    [Fact]
    public void PublicIpv6_CanBeCorroborated()
    {
        var result = NetworkEvidenceEvaluator.Evaluate("xmrig", IPAddress.Parse("2001:db8::10"), 3333);
        Assert.True(result.IsSuspicious);
    }

    [Fact]
    public void IndependentHighConfidenceProcessEvidence_CorroboratesMiningPort()
    {
        var process = new ProcessInfo
        {
            Name = "worker",
            Score = new ThreatScore
            {
                Confidence = DetectionConfidence.High,
                Signals =
                [
                    new ThreatSignal
                    {
                        EvidenceId = "source-evidence",
                        Name = "Malicious command pattern",
                        Category = SignalCategory.CommandLine,
                        Confidence = DetectionConfidence.High,
                        Weight = 55
                    }
                ]
            }
        };

        var result = NetworkEvidenceEvaluator.Evaluate("worker", IPAddress.Parse("203.0.113.10"), 3333, process);

        Assert.True(result.IsSuspicious);
        Assert.Equal(DetectionConfidence.High, result.Confidence);
        Assert.Contains(result.Evidence, item => item.SourceEvidenceId == "source-evidence");
    }

    [Fact]
    public void UnsignedIdentityAlone_DoesNotCreateNetworkAlert()
    {
        var process = new ProcessInfo { Name = "worker", IsSigned = false };
        var result = NetworkEvidenceEvaluator.Evaluate("worker", IPAddress.Parse("203.0.113.10"), 443, process);
        Assert.False(result.IsSuspicious);
        Assert.Empty(result.Evidence);
    }

    [Fact]
    public void AuthenticatedReputationMatch_CreatesProvenancedHighConfidenceEvidence()
    {
        var reputation = new NetworkReputationSet
        {
            FeedVersion = "2026.9.1",
            Source = "Test Feed",
            IssuedUtc = DateTime.UtcNow.AddMinutes(-1),
            ExpiresUtc = DateTime.UtcNow.AddHours(1),
            MaliciousIpAddresses = ["203.0.113.25"]
        };

        var result = NetworkEvidenceEvaluator.Evaluate("browser", IPAddress.Parse("203.0.113.25"), 443, reputation: reputation);

        Assert.True(result.IsSuspicious);
        Assert.Equal(DetectionConfidence.High, result.Confidence);
        Assert.Contains(result.Evidence, item => item.RuleId == "reputation.malicious-ip" && item.Description.Contains("Test Feed"));
    }
}
