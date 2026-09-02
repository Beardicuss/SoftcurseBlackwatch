using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Detection;

/// <summary>Orchestrates normalized evidence collection and an explainable decision.</summary>
public sealed class ThreatScorer
{
    private readonly BlackwatchLogger _logger;
    private readonly BlackwatchConfig _config;
    private readonly DetectionDecisionEngine _decisionEngine;
    private readonly Dictionary<ProcessIdentity, CpuTracker> _cpuTrackers = [];

    private static readonly string[] MinerNames = ["xmrig", "cpuminer", "minerd", "cgminer", "bfgminer", "nbminer", "phoenixminer", "t-rex", "gminer", "lolminer", "nicehash", "ethminer", "claymore", "nanominer", "teamredminer", "wildrig", "srbminer", "ccminer"];
    private static readonly string[] MinerCommands = ["--algo", "-a cryptonight", "--stratum", "stratum+tcp", "stratum+ssl", "--donate", "-o pool.", "--coin", "--randomx", "-p x", "pool.minexmr", "gulf.moneroocean", "rx/0", "kawpow"];
    private static readonly string[] UserWritablePaths = [@"\AppData\Local\Temp", @"\Windows\Temp", @"\Users\Public\", @"\Downloads\", @"\AppData\Roaming\"];
    private static readonly string[] RatNames = ["darkcomet", "njrat", "asyncrat", "quasar", "nanocore", "remcos", "warzone", "orcus", "netwire", "adwind", "poisonivy", "gh0st", "blackshades", "cobaltstrike", "meterpreter", "mimikatz", "lazagne"];
    private static readonly string[] MaliciousCommands = ["reverse_tcp", "reverse_http", "reverse_https", "meterpreter", "ncat -e", "nc.exe -e", "/bin/bash -i", "tcpclient", "invoke-powershelltcp", "powercat", "-encodedcommand", "-enc ", "frombase64string", "iex(", "downloadstring", "invoke-expression", "hidden -ep bypass", "-windowstyle hidden", "sekurlsa", "logonpasswords", "lsadump", "hashdump"];
    private static readonly HashSet<string> SuspiciousParents = new(StringComparer.OrdinalIgnoreCase) { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32" };
    private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase) { "system", "idle", "svchost", "csrss", "wininit", "winlogon", "services", "lsass", "smss", "dwm", "explorer", "taskhostw", "runtimebroker", "searchhost", "shellexperiencehost", "startmenuexperiencehost", "textinputhost", "sihost", "ctfmon", "fontdrvhost", "registry", "memorycompression", "securityhealthservice", "spoolsv", "audiodg", "conhost", "dllhost", "dashost", "wmiprvse", "msdtc" };

    public ThreatScorer(BlackwatchLogger logger, BlackwatchConfig? config = null, DetectionRuleSet? ruleSet = null)
    {
        _logger = logger;
        _config = config ?? new BlackwatchConfig();
        ruleSet ??= new DetectionRuleSet();
        ruleSet.Validate();
        _decisionEngine = new DetectionDecisionEngine(ruleSet);
    }

    public ProcessInfo Score(ProcessInfo process)
    {
        if (IsTrusted(process))
        {
            process.Score = new ThreatScore { Explanation = "Excluded by a trusted application identity rule." };
            return process;
        }

        process.Score = _decisionEngine.Decide(CollectEvidence(process));
        if (process.Score.Level >= ThreatLevel.Suspicious)
            _logger.Threat("ThreatScorer", $"[{process.Score.Level}/{process.Score.Confidence}] {process.Name} (PID {process.Pid}) — Score {process.Score.Total} — {process.Score.RecommendedAction}");
        return process;
    }

    public List<ProcessInfo> ScoreAll(List<ProcessInfo> processes, CancellationToken cancellationToken = default)
    {
        foreach (var process in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Score(process);
        }
        var active = processes.Select(ProcessIdentity.From).ToHashSet();
        foreach (var stale in _cpuTrackers.Keys.Except(active).ToList()) _cpuTrackers.Remove(stale);
        return processes;
    }

    public List<ThreatReport> GenerateReports(List<ProcessInfo> processes, ThreatLevel minLevel = ThreatLevel.Low, CancellationToken cancellationToken = default)
    {
        var reports = new List<ThreatReport>();
        foreach (var process in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (process.Score.Level >= minLevel)
                reports.Add(new ThreatReport { Process = process, Score = process.Score, Timestamp = DateTime.Now });
        }
        return reports.OrderByDescending(report => report.Score.Total).ToList();
    }

    private List<DetectionObservation> CollectEvidence(ProcessInfo process)
    {
        var observations = new List<DetectionObservation>();
        var name = process.Name.ToLowerInvariant();
        var command = process.CommandLine.ToLowerInvariant();
        var writablePath = UserWritablePaths.FirstOrDefault(p => process.FilePath.Contains(p, StringComparison.OrdinalIgnoreCase));

        AddPattern(observations, MinerNames, name, "process.known-miner-name", "Process name matches a known miner pattern");
        AddPattern(observations, MinerCommands, command, "command.mining", "Command line contains a mining protocol or option");
        if (writablePath is not null) observations.Add(new("path.user-writable", "Executable is running from a user-writable location", process.FilePath));
        if (string.IsNullOrEmpty(process.FilePath) && !SystemProcesses.Contains(process.Name)) observations.Add(new("process.path-unavailable", "Executable path could not be collected; this is telemetry degradation, not proof of injection", "unavailable"));
        if (!process.HasWindow && process.CpuPercent > 50 && !SystemProcesses.Contains(process.Name)) observations.Add(new("behavior.background-high-cpu", "Background process currently has high CPU usage", $"{process.CpuPercent:F1}%"));
        TrackSustainedCpu(process, observations);
        if (SuspiciousParents.Contains(process.ParentName) && !SystemProcesses.Contains(process.Name)) observations.Add(new("process.suspicious-parent", "Process was launched by a commonly abused script host", $"{process.ParentName} ({process.ParentPid})"));
        var impersonated = new[] { "svchost", "csrss", "winlogon", "lsass", "services" }.FirstOrDefault(s => name.Contains(s) && name != s);
        if (impersonated is not null) observations.Add(new("process.system-name-impersonation", "Process name resembles a protected Windows process", $"{process.Name} -> {impersonated}"));
        if (process.MemoryMB > 2048 && !SystemProcesses.Contains(process.Name)) observations.Add(new("behavior.high-memory", "Process has unusually high working-set memory", $"{process.MemoryMB:F0} MB"));
        if (process.IsSigned == false && writablePath is not null && !SystemProcesses.Contains(process.Name)) observations.Add(new("file.unsigned-user-writable", "Unsigned executable is running from a user-writable location", process.FilePath));
        AddPattern(observations, RatNames, name, "process.known-rat-name", "Process name matches a known remote-access malware family");
        AddPattern(observations, MaliciousCommands, command, "command.malicious", "Command line contains a high-risk execution pattern");
        return observations;
    }

    private void TrackSustainedCpu(ProcessInfo process, ICollection<DetectionObservation> observations)
    {
        var identity = ProcessIdentity.From(process);
        if (process.CpuPercent <= _config.CpuSpikeThresholdPercent || SystemProcesses.Contains(process.Name))
        {
            _cpuTrackers.Remove(identity);
            return;
        }
        if (!_cpuTrackers.TryGetValue(identity, out var tracker)) _cpuTrackers[identity] = tracker = new CpuTracker();
        tracker.Strikes++;
        var elapsed = (DateTime.UtcNow - tracker.FirstSeenUtc).TotalSeconds;
        if (elapsed >= _config.CpuSpikeDurationSeconds)
            observations.Add(new("behavior.sustained-high-cpu", "CPU usage remained above the configured threshold", $"{process.CpuPercent:F1}% for {elapsed:F0}s ({tracker.Strikes} samples)"));
    }

    private bool IsTrusted(ProcessInfo process)
    {
        var now = DateTime.UtcNow;
        return _config.TrustedApplications.Any(rule => MatchesTrustedIdentity(rule, process, now));
    }

    private static bool MatchesTrustedIdentity(TrustedApplication rule, ProcessInfo process, DateTime now)
    {
        try
        {
            return (rule.ExpiresUtc is null || rule.ExpiresUtc > now) &&
                rule.Sha256?.Length == 64 &&
                process.FileHash.Equals(rule.Sha256, StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(rule.CanonicalPath) &&
                !string.IsNullOrWhiteSpace(process.FilePath) &&
                Path.GetFullPath(process.FilePath).Equals(Path.GetFullPath(rule.CanonicalPath), StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(rule.PublisherThumbprint) ||
                 process.PublisherThumbprint.Equals(rule.PublisherThumbprint, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }

    private static void AddPattern(ICollection<DetectionObservation> target, IEnumerable<string> patterns, string input, string ruleId, string description)
    {
        if (string.IsNullOrEmpty(input)) return;
        var match = patterns.FirstOrDefault(input.Contains);
        if (match is not null) target.Add(new(ruleId, description, match));
    }

    private sealed class CpuTracker { public int Strikes { get; set; } public DateTime FirstSeenUtc { get; } = DateTime.UtcNow; }
    private readonly record struct ProcessIdentity(int Pid, DateTime StartTime)
    {
        public static ProcessIdentity From(ProcessInfo process) => new(process.Pid, process.StartTime);
    }
}
