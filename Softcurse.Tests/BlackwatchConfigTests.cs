using Softcurse.Shared.Config;
using Xunit;

namespace Softcurse.Tests;

public class BlackwatchConfigTests
{
    [Fact]
    public void Save_RejectsInvalidScanIntervalWithoutWriting()
    {
        var config = new BlackwatchConfig { ScanIntervalMs = 10 };

        var saved = config.Save();

        Assert.False(saved);
        Assert.Contains("Scan interval", BlackwatchConfig.LastPersistenceError);
    }
}
