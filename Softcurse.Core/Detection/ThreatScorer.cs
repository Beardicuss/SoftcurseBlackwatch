using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

/// <summary>
/// Heuristic threat scoring engine.
/// Applies weighted signals — no single signal convicts.
/// Thresholds: 50 = Suspicious, 75 = High, 90 = Critical.
/// </summary>
public class ThreatScorer
{
    private readonly SentinelLogger _logger;
    private readonly Dictionary<int, CpuTracker> _cpuTrackers = new();

    // ── Known Miner Process Names ──
    private static readonly string[] MinerPatterns =
    {
        "xmrig", "cpuminer", "minerd", "cgminer", "bfgminer",
        "nbminer", "phoenixminer", "t-rex", "gminer", "lolminer",
        "nicehash", "ethminer", "claymore", "nanominer",
        "teamredminer", "wildrig", "srbminer", "ccminer",
    };

    // ── Known Miner Command-Line Flags ──
    private static readonly string[] MinerCmdPatterns =
    {
        "--algo", "-a cryptonight", "--stratum", "stratum+tcp",
        "stratum+ssl", "--donate", "-o pool.", "--coin",
        "--randomx", "-p x", "--tls", "pool.minexmr",
        "gulf.moneroocean", "rx/0", "kawpow",
    };

    // ── Suspicious Execution Paths ──
    private static readonly string[] SuspiciousPaths =
    {
        @"\AppData\Local\Temp",
        @"\Windows\Temp",
        @"\Users\Public\",
        @"\Downloads\",
        @"\AppData\Roaming\",
    };

    // ── Suspicious Parent-Child Chains ──
    // (e.g. cmd → svchost-lookalike)
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32",
    };

    // ── Known System Processes (white-list for "no path" check) ──
    private static readonly HashSet<string> KnownSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "svchost", "csrss", "wininit", "winlogon",
        "services", "lsass", "smss", "dwm", "explorer", "taskhostw",
        "runtimebroker", "searchhost", "shellexperiencehost",
        "startmenuexperiencehost", "textinputhost", "sihost",
        "ctfmon", "fontdrvhost", "registry", "memorycompression",
        "securityhealthservice", "spoolsv", "audiodg", "conhost",
        "dllhost", "dashost", "wmiprvse", "msdtc",
    };

    public ThreatScorer(SentinelLogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Score a single process. Returns the process with updated Score.
    /// </summary>
    public ProcessInfo Score(ProcessInfo proc)
    {
        var signals = new List<ThreatSignal>();

        // ── 1. Known Miner Name (+50) ──
        var lower = proc.Name.ToLowerInvariant();
        foreach (var pattern in MinerPatterns)
        {
            if (lower.Contains(pattern))
            {
                signals.Add(new ThreatSignal
                {
                    Name = "KnownMinerName",
                    Description = $"Process name matches known miner: {pattern}",
                    Weight = 50,
                    Category = SignalCategory.ProcessName
                });
                break;
            }
        }

        // ── 2. Miner Command-Line Args (+40) ──
        if (!string.IsNullOrEmpty(proc.CommandLine))
        {
            var cmdLower = proc.CommandLine.ToLowerInvariant();
            foreach (var flag in MinerCmdPatterns)
            {
                if (cmdLower.Contains(flag))
                {
                    signals.Add(new ThreatSignal
                    {
                        Name = "MinerCmdArgs",
                        Description = $"Command line contains mining flag: {flag}",
                        Weight = 40,
                        Category = SignalCategory.CommandLine
                    });
                    break;
                }
            }
        }

        // ── 3. Suspicious Path (+20) ──
        if (!string.IsNullOrEmpty(proc.FilePath))
        {
            foreach (var path in SuspiciousPaths)
            {
                if (proc.FilePath.Contains(path, StringComparison.OrdinalIgnoreCase))
                {
                    signals.Add(new ThreatSignal
                    {
                        Name = "SuspiciousPath",
                        Description = $"Running from: {path}",
                        Weight = 20,
                        Category = SignalCategory.FilePath
                    });
                    break;
                }
            }
        }

        // ── 4. No Executable Path (possible injection) (+20) ──
        if (string.IsNullOrEmpty(proc.FilePath) && !KnownSystemProcesses.Contains(proc.Name))
        {
            signals.Add(new ThreatSignal
            {
                Name = "NoExecutablePath",
                Description = "No executable path found — possible code injection",
                Weight = 20,
                Category = SignalCategory.Signature
            });
        }

        // ── 5. Background + High CPU (+30) ──
        if (!proc.HasWindow && proc.CpuPercent > 50 && !KnownSystemProcesses.Contains(proc.Name))
        {
            signals.Add(new ThreatSignal
            {
                Name = "BackgroundHighCpu",
                Description = $"Background process using {proc.CpuPercent:F1}% CPU",
                Weight = 30,
                Category = SignalCategory.CpuBehavior
            });
        }

        // ── 6. Suspicious Parent Chain (+25) ──
        if (SuspiciousParents.Contains(proc.ParentName) && !KnownSystemProcesses.Contains(proc.Name))
        {
            signals.Add(new ThreatSignal
            {
                Name = "SuspiciousParent",
                Description = $"Spawned by {proc.ParentName} (PID {proc.ParentPid})",
                Weight = 25,
                Category = SignalCategory.ParentChain
            });
        }

        // ── 7. Name Impersonation (+35) ──
        // e.g. "svchost_" or "csrss " trying to look like system processes
        foreach (var sysName in new[] { "svchost", "csrss", "winlogon", "lsass", "services" })
        {
            if (lower.Contains(sysName) && lower != sysName)
            {
                signals.Add(new ThreatSignal
                {
                    Name = "NameImpersonation",
                    Description = $"Name '{proc.Name}' impersonates system process '{sysName}'",
                    Weight = 35,
                    Category = SignalCategory.ProcessName
                });
                break;
            }
        }

        // ── 8. Very High Memory for Unknown Process (+15) ──
        if (proc.MemoryMB > 2048 && !KnownSystemProcesses.Contains(proc.Name))
        {
            signals.Add(new ThreatSignal
            {
                Name = "HighMemory",
                Description = $"Using {proc.MemoryMB:F0} MB RAM",
                Weight = 15,
                Category = SignalCategory.CpuBehavior
            });
        }

        proc.Score = new ThreatScore { Signals = signals };

        if (proc.Score.Level >= ThreatLevel.Suspicious)
        {
            _logger.Threat("ThreatScorer",
                $"[{proc.Score.Level}] {proc.Name} (PID {proc.Pid}) — Score {proc.Score.Total} — {proc.Score.RecommendedAction}");
        }

        return proc;
    }

    /// <summary>
    /// Score all processes in a batch.
    /// </summary>
    public List<ProcessInfo> ScoreAll(List<ProcessInfo> processes)
    {
        foreach (var proc in processes)
            Score(proc);
        return processes;
    }

    /// <summary>
    /// Generate threat reports for all processes above a minimum level.
    /// </summary>
    public List<ThreatReport> GenerateReports(List<ProcessInfo> processes, ThreatLevel minLevel = ThreatLevel.Low)
    {
        return processes
            .Where(p => p.Score.Level >= minLevel)
            .Select(p => new ThreatReport
            {
                Process = p,
                Score = p.Score,
                Timestamp = DateTime.Now
            })
            .OrderByDescending(r => r.Score.Total)
            .ToList();
    }

    // ── CPU Tracking Helper ──
    private class CpuTracker
    {
        public int Strikes { get; set; }
        public DateTime FirstSeen { get; set; } = DateTime.Now;
    }
}
