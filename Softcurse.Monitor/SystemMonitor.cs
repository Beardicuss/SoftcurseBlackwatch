using System.Diagnostics;
using System.Management;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>
/// Monitors system-wide CPU and Memory using PerformanceCounter + WMI.
/// Stores samples for behavior analysis.
/// </summary>
public class SystemMonitor : IDisposable
{
    private readonly PerformanceCounter _cpuCounter;
    private readonly SentinelLogger _logger;
    private readonly List<SystemSnapshot> _history = new();
    private readonly int _maxHistory;

    public IReadOnlyList<SystemSnapshot> History => _history;

    public SystemMonitor(SentinelLogger logger, int maxHistorySize = 120)
    {
        _logger = logger;
        _maxHistory = maxHistorySize;
        _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
        _cpuCounter.NextValue(); // Prime
    }

    /// <summary>
    /// Takes a snapshot of current system resource usage.
    /// </summary>
    public SystemSnapshot GetSnapshot()
    {
        var cpuUsage = _cpuCounter.NextValue();
        float totalMemMB = 0, usedMemMB = 0;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                var totalKB = Convert.ToSingle(obj["TotalVisibleMemorySize"]);
                var freeKB = Convert.ToSingle(obj["FreePhysicalMemory"]);
                totalMemMB = totalKB / 1024f;
                usedMemMB = (totalKB - freeKB) / 1024f;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("SystemMonitor", $"WMI memory query failed: {ex.Message}");
        }

        var snapshot = new SystemSnapshot
        {
            CpuUsagePercent = cpuUsage,
            MemoryTotalMB = totalMemMB,
            MemoryUsedMB = usedMemMB,
        };

        _history.Add(snapshot);
        if (_history.Count > _maxHistory)
            _history.RemoveAt(0);

        return snapshot;
    }

    public void Dispose()
    {
        _cpuCounter.Dispose();
        GC.SuppressFinalize(this);
    }
}
