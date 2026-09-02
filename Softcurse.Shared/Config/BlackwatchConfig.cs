using System.Text.Json;
using Softcurse.Shared.Security;

namespace Softcurse.Shared.Config;

/// <summary>
/// Configuration for Softcurse Blackwatch. Persisted to JSON.
/// </summary>
public class BlackwatchConfig
{
    public static string? LastPersistenceError { get; private set; }
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
        "SoftcurseBlackwatch", "Quarantine");

    /// <summary>Monitoring poll interval in milliseconds.</summary>
    public int MonitorIntervalMs { get; set; } = 1000;

    /// <summary>Process scan interval in milliseconds.</summary>
    public int ScanIntervalMs { get; set; } = 3000;

    /// <summary>Legacy process-name entries retained for migration/display only; they do not suppress detection.</summary>
    public List<string> Whitelist { get; set; } = new();

    /// <summary>Identity-bound exceptions. At least one identity field must match in addition to name.</summary>
    public List<TrustedApplication> TrustedApplications { get; set; } = new();

    /// <summary>Minimize to system tray instead of closing.</summary>
    public bool MinimizeToTray { get; set; } = true;

    // ── Persistence ──

    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SoftcurseBlackwatch");
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.json");
    private static readonly string LegacyConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SoftcurseSentinel", "config.json");

    public static BlackwatchConfig Load()
    {
        LastPersistenceError = null;
        try
        {
            var sourcePath = File.Exists(ConfigPath) ? ConfigPath : LegacyConfigPath;
            if (File.Exists(sourcePath))
            {
                ProtectedLocalStorage.EnsurePrivateDirectory(Path.GetDirectoryName(sourcePath)!);
                ProtectedLocalStorage.EnsurePrivateFile(sourcePath);
                var json = File.ReadAllText(sourcePath);
                var config = JsonSerializer.Deserialize<BlackwatchConfig>(json) ?? new BlackwatchConfig();
                config.NormalizeAndValidate();
                if (sourcePath == LegacyConfigPath)
                {
                    var legacyDefaultQuarantine = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "SoftcurseSentinel", "Quarantine");
                    if (string.Equals(config.QuarantinePath, legacyDefaultQuarantine, StringComparison.OrdinalIgnoreCase))
                        config.QuarantinePath = new BlackwatchConfig().QuarantinePath;
                    config.Save();
                }
                return config;
            }
        }
        catch (Exception ex)
        {
            LastPersistenceError = $"Could not load configuration: {ex.Message}";
        }
        return new BlackwatchConfig();
    }

    public bool Save()
    {
        string? temporaryPath = null;
        try
        {
            Validate();
            ProtectedLocalStorage.EnsurePrivateDirectory(ConfigDir);
            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            temporaryPath = Path.Combine(ConfigDir, $"config.{Guid.NewGuid():N}.tmp");
            File.WriteAllText(temporaryPath, json);
            File.Move(temporaryPath, ConfigPath, overwrite: true);
            ProtectedLocalStorage.EnsurePrivateFile(ConfigPath);
            LastPersistenceError = null;
            return true;
        }
        catch (Exception ex)
        {
            LastPersistenceError = $"Could not save configuration: {ex.Message}";
            return false;
        }
        finally
        {
            if (temporaryPath is not null)
            {
                try { File.Delete(temporaryPath); } catch { }
            }
        }
    }

    private void Validate()
    {
        if (CpuSpikeThresholdPercent is < 1 or > 100)
            throw new InvalidDataException("CPU spike threshold must be between 1 and 100.");
        if (CpuSpikeDurationSeconds is < 1 or > 3600)
            throw new InvalidDataException("CPU spike duration must be between 1 and 3600 seconds.");
        if (MonitorIntervalMs is < 250 or > 60000)
            throw new InvalidDataException("Monitor interval must be between 250 and 60000 ms.");
        if (ScanIntervalMs is < 1000 or > 3600000)
            throw new InvalidDataException("Scan interval must be between 1000 and 3600000 ms.");
        if (string.IsNullOrWhiteSpace(QuarantinePath))
            throw new InvalidDataException("Quarantine path cannot be empty.");
        if (TrustedApplications.Any(rule => string.IsNullOrWhiteSpace(rule.TrustId)))
            throw new InvalidDataException("Every trusted application must include a stable trust ID.");
        if (TrustedApplications.Select(rule => rule.TrustId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != TrustedApplications.Count)
            throw new InvalidDataException("Trusted application IDs must be unique.");
        if (TrustedApplications.Any(rule => rule.Sha256?.Length != 64 || !rule.Sha256.All(Uri.IsHexDigit)))
            throw new InvalidDataException("Every trusted application must include a valid SHA-256 identity.");
        if (TrustedApplications.Any(rule => string.IsNullOrWhiteSpace(rule.CanonicalPath) || !Path.IsPathFullyQualified(rule.CanonicalPath)))
            throw new InvalidDataException("Every trusted application must include a canonical absolute path.");
    }

    private void NormalizeAndValidate()
    {
        Whitelist ??= [];
        TrustedApplications ??= [];
        foreach (var rule in TrustedApplications)
        {
            if (string.IsNullOrWhiteSpace(rule.TrustId))
                rule.TrustId = Guid.NewGuid().ToString("N");
            if (rule.CreatedUtc == default)
                rule.CreatedUtc = DateTime.UtcNow;
            rule.Sha256 = rule.Sha256.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(rule.CanonicalPath))
                rule.CanonicalPath = Path.GetFullPath(rule.CanonicalPath);
        }
        Validate();
    }
}

public sealed class TrustedApplication
{
    public string TrustId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string CanonicalPath { get; set; } = string.Empty;
    public string PublisherThumbprint { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTime CreatedUtc { get; set; }
    public DateTime? ExpiresUtc { get; set; }
}
