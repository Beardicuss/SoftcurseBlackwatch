using Softcurse.Shared.Config;
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
    private readonly SentinelConfig _config;
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

    // ── Known RAT / Trojan Process Names ──
    private static readonly string[] RatPatterns =
    {
        "darkcomet", "njrat", "asyncrat", "quasar", "nanocore",
        "remcos", "warzone", "orcus", "netwire", "adwind",
        "poisonivy", "gh0st", "blackshades", "havoc", "cobalt",
        "cobaltstrike", "meterpreter", "mimikatz", "lazagne",
        "empire", "sliver", "brute", "rat", "keylog",
    };

    // ── Reverse Shell / Keylogger Command-Line Indicators ──
    private static readonly string[] MaliciousCmdPatterns =
    {
        // Reverse shells
        "reverse_tcp", "reverse_http", "reverse_https", "meterpreter",
        "ncat -e", "nc.exe -e", "/bin/bash -i", "TCPClient",
        "System.Net.Sockets", "Invoke-PowerShellTcp", "powercat",
        // Encoded/obfuscated
        "-encodedcommand", "-enc ", "frombase64string", "iex(",
        "downloadstring", "invoke-expression", "invoke-webrequest",
        "hidden -ep bypass", "-windowstyle hidden",
        // Credential stealing
        "sekurlsa", "logonpasswords", "lsadump", "hashdump",
        "lazagne", "credential",
    };

    // ── Suspicious C2/RAT Ports ──
    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 5555, 1337, 1234, 6666, 7777,  // Common RAT defaults
        8080, 8443, 443, 80,                   // C2 over HTTP/S
        4443, 4445, 9090, 31337,               // Known C2 ports
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

    public ThreatScorer(SentinelLogger logger, SentinelConfig? config = null)
    {
        _logger = logger;
        _config = config ?? new SentinelConfig();
    }

    /// <summary>
    /// Score a single process. Returns the process with updated Score.
    /// </summary>
    public ProcessInfo Score(ProcessInfo proc)
    {
        // Whitelist bypass — skip scoring for excluded processes
        if (_config.Whitelist.Any(w =>
            proc.Name.Equals(w, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(proc.FilePath) && proc.FilePath.Contains(w, StringComparison.OrdinalIgnoreCase))))
        {
            proc.Score = new ThreatScore();
            return proc;
        }

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

        // ── 6. Sustained High CPU (+35) ──
        if (proc.CpuPercent > _config.CpuSpikeThresholdPercent && !KnownSystemProcesses.Contains(proc.Name))
        {
            if (!_cpuTrackers.TryGetValue(proc.Pid, out var tracker))
            {
                tracker = new CpuTracker();
                _cpuTrackers[proc.Pid] = tracker;
            }
            tracker.Strikes++;
            var elapsed = (DateTime.Now - tracker.FirstSeen).TotalSeconds;
            if (elapsed >= _config.CpuSpikeDurationSeconds)
            {
                signals.Add(new ThreatSignal
                {
                    Name = "SustainedHighCpu",
                    Description = $"CPU above {_config.CpuSpikeThresholdPercent}% for {elapsed:F0}s ({tracker.Strikes} samples)",
                    Weight = 35,
                    Category = SignalCategory.CpuBehavior
                });
            }
        }
        else
        {
            _cpuTrackers.Remove(proc.Pid);
        }

        // ── 7. Suspicious Parent Chain (+25) ──
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

        // ── 8. Name Impersonation (+35) ──
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

        // ── 9. Very High Memory for Unknown Process (+15) ──
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

        // ── 10. Unsigned Executable in Suspicious Location (+15) ──
        if (proc.IsSigned == false && !KnownSystemProcesses.Contains(proc.Name)
            && !string.IsNullOrEmpty(proc.FilePath)
            && SuspiciousPaths.Any(p => proc.FilePath.Contains(p, StringComparison.OrdinalIgnoreCase)))
        {
            signals.Add(new ThreatSignal
            {
                Name = "UnsignedExecutable",
                Description = "Unsigned binary running from suspicious path",
                Weight = 15,
                Category = SignalCategory.Signature
            });
        }

        // ── 11. Known RAT Name Match (+45) ──
        foreach (var ratName in RatPatterns)
        {
            if (lower.Contains(ratName))
            {
                signals.Add(new ThreatSignal
                {
                    Name = "KnownRAT",
                    Description = $"Process name matches known RAT/trojan: {ratName}",
                    Weight = 45,
                    Category = SignalCategory.ProcessName
                });
                break;
            }
        }

        // ── 12. Malicious Command-Line (+40) ──
        if (!string.IsNullOrEmpty(proc.CommandLine))
        {
            var cmdLower = proc.CommandLine.ToLowerInvariant();
            foreach (var pattern in MaliciousCmdPatterns)
            {
                if (cmdLower.Contains(pattern))
                {
                    signals.Add(new ThreatSignal
                    {
                        Name = "MaliciousCommand",
                        Description = $"Command line contains: {pattern}",
                        Weight = 40,
                        Category = SignalCategory.CommandLine
                    });
                    break;
                }
            }
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
