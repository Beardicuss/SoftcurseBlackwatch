using System.Text.Json;

namespace Softcurse.Shared.Config;

/// <summary>
/// Configuration for Softcurse Sentinel. Persisted to JSON.
/// </summary>
public class SentinelConfig
{
    /// <summary>Seconds of sustained high CPU before flagging.</summary>
    public int CpuSpikeThresholdPercent { get; set; } = 70;
    public int CpuSpikeDurationSeconds { get; set; } = 15;

    /// <summary>Enable auto-action on Critical threats.</summary>
    public bool AutoActionEnabled { get; set; } = false;

    /// <summary>Dry-run mode: log actions but don't execute them.</summary>
    public bool DryRunMode { get; set; } = true;

    /// <summary>Quarantine directory path.</summary>
    public string QuarantinePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SoftcurseSentinel", "Quarantine");

    /// <summary>Monitoring poll interval in milliseconds.</summary>
    public int MonitorIntervalMs { get; set; } = 1000;

    /// <summary>Process scan interval in milliseconds.</summary>
    public int ScanIntervalMs { get; set; } = 3000;

    // ── Persistence ──

    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SoftcurseSentinel");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");

    public static SentinelConfig Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<SentinelConfig>(json) ?? new SentinelConfig();
            }
        }
        catch { }
        return new SentinelConfig();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(ConfigPath, json);
        }
        catch { }
    }
}
