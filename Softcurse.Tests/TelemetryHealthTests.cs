using Softcurse.Shared.Models;
using Xunit;

namespace Softcurse.Tests;

public sealed class TelemetryHealthTests
{
    [Fact]
    public void Combine_UsesWorstHealthAndRetainsIssues()
    {
        var result = TelemetryHealth.Combine(
            TelemetryHealth.Healthy(),
            TelemetryHealth.Degraded("IPv6 telemetry unavailable."),
            TelemetryHealth.Error("Process scan failed."));

        Assert.Equal(TelemetryHealthLevel.Error, result.Level);
        Assert.Contains("IPv6 telemetry unavailable.", result.Message);
        Assert.Contains("Process scan failed.", result.Message);
    }

    [Fact]
    public void Combine_AllHealthy_ReturnsHealthyWithoutComponentNoise()
    {
        var result = TelemetryHealth.Combine(
            TelemetryHealth.Healthy("Processes operational."),
            TelemetryHealth.Healthy("Network operational."));

        Assert.Equal(TelemetryHealthLevel.Healthy, result.Level);
        Assert.Equal("All enabled collectors are operational.", result.Message);
    }

    [Fact]
    public void Combine_NoReports_IsError()
    {
        var result = TelemetryHealth.Combine();

        Assert.Equal(TelemetryHealthLevel.Error, result.Level);
    }
}
