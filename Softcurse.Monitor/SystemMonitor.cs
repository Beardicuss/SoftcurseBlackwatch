using System.Diagnostics;
using System.Management;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>
/// Monitors system-wide CPU and Memory using PerformanceCounter + WMI.
/// Thread-safe history storage.
/// </summary>
public class SystemMonitor : IDisposable
{
    private readonly PerformanceCounter _cpuCounter;
    private readonly BlackwatchLogger _logger;
    private readonly object _historyLock = new();
    private readonly List<SystemSnapshot> _history = new();
    private readonly int _maxHistory;
    public TelemetryHealth LastHealth { get; private set; } = TelemetryHealth.Error("System telemetry has not completed yet.");

    public IReadOnlyList<SystemSnapshot> History
    {
        get
        {
            lock (_historyLock) return _history.ToList();
        }
    }

    public SystemMonitor(BlackwatchLogger logger, int maxHistorySize = 120)
    {
        _logger = logger;
        _maxHistory = maxHistorySize;
        _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
        _cpuCounter.NextValue(); // Prime
    }

    /// <summary>
    /// Takes a snapshot of current system resource usage. Thread-safe.
    /// </summary>
    public SystemSnapshot GetSnapshot(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cpuUsage = _cpuCounter.NextValue();
        float totalMemMB = 0, usedMemMB = 0;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT TotalVisibleMemorySize, FreePhysicalMemory FROM Win32_OperatingSystem");
            foreach (var obj in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var totalKB = Convert.ToSingle(obj["TotalVisibleMemorySize"]);
                var freeKB = Convert.ToSingle(obj["FreePhysicalMemory"]);
                totalMemMB = totalKB / 1024f;
                usedMemMB = (totalKB - freeKB) / 1024f;
            }
            LastHealth = totalMemMB > 0
                ? TelemetryHealth.Healthy("System telemetry is operational.")
                : TelemetryHealth.Degraded("Memory telemetry returned no operating-system data.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            LastHealth = TelemetryHealth.Degraded($"Memory telemetry is unavailable: {ex.Message}");
            _logger.Warning("SystemMonitor", $"WMI memory query failed: {ex.Message}");
        }

        var snapshot = new SystemSnapshot
        {
            CpuUsagePercent = cpuUsage,
            MemoryTotalMB = totalMemMB,
            MemoryUsedMB = usedMemMB,
        };

        lock (_historyLock)
        {
            _history.Add(snapshot);
            if (_history.Count > _maxHistory)
                _history.RemoveAt(0);
        }

        return snapshot;
    }

    public void Dispose()
    {
        _cpuCounter.Dispose();
        GC.SuppressFinalize(this);
    }
}
