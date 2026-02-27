namespace Softcurse.Shared.Models;

// ═══════════════════════════════════════════════════
// Softcurse Sentinel — Shared Data Models
// ═══════════════════════════════════════════════════

/// <summary>
/// Full metadata about a running process.
/// </summary>
public class ProcessInfo
{
    public int Pid { get; set; }
    public string Name { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string CommandLine { get; set; } = string.Empty;
    public int ParentPid { get; set; }
    public string ParentName { get; set; } = string.Empty;
    public double CpuPercent { get; set; }
    public double MemoryMB { get; set; }
    public int ThreadCount { get; set; }
    public bool HasWindow { get; set; }
    public DateTime StartTime { get; set; }
    public string FileHash { get; set; } = string.Empty;  // SHA256
    public bool? IsSigned { get; set; }  // Authenticode: true=signed, false=unsigned, null=unknown
    public ThreatScore Score { get; set; } = new();
}

/// <summary>
/// Weighted threat score with individual signal breakdowns.
/// </summary>
public class ThreatScore
{
    public int Total => Signals.Sum(s => s.Weight);
    public ThreatLevel Level => Total switch
    {
        >= 90 => ThreatLevel.Critical,
        >= 75 => ThreatLevel.High,
        >= 50 => ThreatLevel.Suspicious,
        >= 25 => ThreatLevel.Low,
        _ => ThreatLevel.Safe
    };
    public List<ThreatSignal> Signals { get; set; } = new();
    public string RecommendedAction => Level switch
    {
        ThreatLevel.Critical => "AUTO-TERMINATE",
        ThreatLevel.High => "QUARANTINE",
        ThreatLevel.Suspicious => "MONITOR",
        ThreatLevel.Low => "LOG",
        _ => "NONE"
    };
}

/// <summary>
/// A single signal contributing to a threat score.
/// </summary>
public class ThreatSignal
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Weight { get; set; }
    public SignalCategory Category { get; set; }
}

/// <summary>
/// Report generated after scanning a process.
/// </summary>
public class ThreatReport
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public ProcessInfo Process { get; set; } = new();
    public ThreatScore Score { get; set; } = new();
    public string RecommendedAction => Score.RecommendedAction;
}

/// <summary>
/// Active network connection with process correlation.
/// </summary>
public class ConnectionInfo
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string LocalEndpoint { get; set; } = string.Empty;
    public string RemoteEndpoint { get; set; } = string.Empty;
    public int RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public bool IsSuspicious { get; set; }
    public string SuspiciousReason { get; set; } = string.Empty;
}

/// <summary>
/// Snapshot of system resource usage.
/// </summary>
public class SystemSnapshot
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public float CpuUsagePercent { get; set; }
    public float MemoryUsedMB { get; set; }
    public float MemoryTotalMB { get; set; }
    public float MemoryUsagePercent => MemoryTotalMB > 0 ? (MemoryUsedMB / MemoryTotalMB) * 100f : 0;
    public int ActiveProcessCount { get; set; }
    public int ActiveConnectionCount { get; set; }
}

/// <summary>
/// Action taken by the cleaner, logged for reversibility.
/// </summary>
public class CleanerAction
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public CleanerActionType ActionType { get; set; }
    public int TargetPid { get; set; }
    public string TargetName { get; set; } = string.Empty;
    public string TargetPath { get; set; } = string.Empty;
    public string? QuarantinePath { get; set; }
    public string? RegistryKey { get; set; }
    public string? RegistryValue { get; set; }
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public bool DryRun { get; set; }
}

/// <summary>
/// A log entry from the Sentinel logger.
/// </summary>
public class LogEntry
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public LogLevel Level { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

// ═══════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════

public enum ThreatLevel
{
    Safe,
    Low,
    Suspicious,
    High,
    Critical
}

public enum SignalCategory
{
    CpuBehavior,
    FilePath,
    ProcessName,
    ParentChain,
    NetworkActivity,
    Signature,
    CommandLine,
    Persistence
}

public enum CleanerActionType
{
    KillProcess,
    DisableAutorun,
    QuarantineFile,
    RemoveStartupEntry
}

public enum LogLevel
{
    Debug,
    Info,
    Warning,
    Threat,
    Error,
    Critical
}
