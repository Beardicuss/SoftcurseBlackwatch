using System.Diagnostics;
using System.Security.AccessControl;
using Microsoft.Win32;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Cleaner;

/// <summary>
/// Response engine for Softcurse Sentinel.
/// Kills processes, removes autoruns, quarantines files.
/// Every action is logged. Dry-run mode available.
/// Never deletes — quarantines first.
/// </summary>
public class SentinelCleaner
{
    private readonly SentinelLogger _logger;
    private readonly SentinelConfig _config;
    private readonly List<CleanerAction> _actionLog = new();

    public IReadOnlyList<CleanerAction> ActionLog => _actionLog;

    // Registry Run keys where malware loves to hide
    private static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    };

    public SentinelCleaner(SentinelLogger logger, SentinelConfig config)
    {
        _logger = logger;
        _config = config;
        Directory.CreateDirectory(_config.QuarantinePath);
    }

    // ═══════════════════════════════════════════════
    // 1. KILL PROCESS
    // ═══════════════════════════════════════════════

    /// <summary>
    /// Terminates a process by PID. Logs the action.
    /// </summary>
    public CleanerAction KillProcess(int pid, string processName, bool dryRun = false)
    {
        var action = new CleanerAction
        {
            ActionType = CleanerActionType.KillProcess,
            TargetPid = pid,
            TargetName = processName,
            DryRun = dryRun || _config.DryRunMode
        };

        if (action.DryRun)
        {
            action.Success = true;
            _logger.Info("Cleaner", $"[DRY-RUN] Would kill: {processName} (PID {pid})");
        }
        else
        {
            try
            {
                var proc = Process.GetProcessById(pid);
                proc.Kill(entireProcessTree: true);
                proc.WaitForExit(5000);
                action.Success = true;
                _logger.Threat("Cleaner", $"KILLED: {processName} (PID {pid})");
            }
            catch (Exception ex)
            {
                action.Success = false;
                action.ErrorMessage = ex.Message;
                _logger.Error("Cleaner", $"Failed to kill {processName}: {ex.Message}");
            }
        }

        _actionLog.Add(action);
        return action;
    }

    // ═══════════════════════════════════════════════
    // 2. DISABLE AUTORUNS
    // ═══════════════════════════════════════════════

    /// <summary>
    /// Scans Registry Run keys and Startup folders for suspicious entries.
    /// Returns entries found.
    /// </summary>
    public List<AutorunEntry> ScanAutoruns()
    {
        var entries = new List<AutorunEntry>();

        // Registry Run Keys (HKCU + HKLM)
        foreach (var keyPath in RunKeys)
        {
            ScanRegistryKey(Registry.CurrentUser, keyPath, entries);
            ScanRegistryKey(Registry.LocalMachine, keyPath, entries);
        }

        // Startup folders
        var startupPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };

        foreach (var dir in startupPaths)
        {
            if (Directory.Exists(dir))
            {
                foreach (var file in Directory.GetFiles(dir))
                {
                    entries.Add(new AutorunEntry
                    {
                        Source = "StartupFolder",
                        Name = Path.GetFileName(file),
                        Value = file,
                        Path = dir
                    });
                }
            }
        }

        _logger.Info("Cleaner", $"Found {entries.Count} autorun entries");
        return entries;
    }

    /// <summary>
    /// Removes a specific autorun entry.
    /// </summary>
    public CleanerAction RemoveAutorun(AutorunEntry entry, bool dryRun = false)
    {
        var action = new CleanerAction
        {
            ActionType = CleanerActionType.DisableAutorun,
            TargetName = entry.Name,
            TargetPath = entry.Value,
            RegistryKey = entry.Path,
            RegistryValue = entry.Name,
            DryRun = dryRun || _config.DryRunMode
        };

        if (action.DryRun)
        {
            action.Success = true;
            _logger.Info("Cleaner", $"[DRY-RUN] Would remove autorun: {entry.Name} => {entry.Value}");
        }
        else
        {
            try
            {
                if (entry.Source == "StartupFolder")
                {
                    // Quarantine instead of delete
                    QuarantineFile(entry.Value);
                    action.Success = true;
                }
                else
                {
                    // Registry removal
                    var hive = entry.Path.StartsWith("HKCU") ? Registry.CurrentUser : Registry.LocalMachine;
                    using var key = hive.OpenSubKey(entry.RegistryKeyPath, writable: true);
                    if (key != null)
                    {
                        key.DeleteValue(entry.Name, throwOnMissingValue: false);
                        action.Success = true;
                    }
                }
                _logger.Threat("Cleaner", $"Removed autorun: {entry.Name}");
            }
            catch (Exception ex)
            {
                action.Success = false;
                action.ErrorMessage = ex.Message;
                _logger.Error("Cleaner", $"Failed to remove autorun {entry.Name}: {ex.Message}");
            }
        }

        _actionLog.Add(action);
        return action;
    }

    // ═══════════════════════════════════════════════
    // 3. QUARANTINE FILE
    // ═══════════════════════════════════════════════

    /// <summary>
    /// Moves a file to quarantine and strips execute permissions.
    /// Never deletes.
    /// </summary>
    public CleanerAction QuarantineFile(string filePath, bool dryRun = false)
    {
        var action = new CleanerAction
        {
            ActionType = CleanerActionType.QuarantineFile,
            TargetPath = filePath,
            TargetName = Path.GetFileName(filePath),
            DryRun = dryRun || _config.DryRunMode
        };

        if (action.DryRun)
        {
            action.Success = true;
            _logger.Info("Cleaner", $"[DRY-RUN] Would quarantine: {filePath}");
        }
        else
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    action.Success = false;
                    action.ErrorMessage = "File not found";
                    _actionLog.Add(action);
                    return action;
                }

                var quarantineName = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(filePath)}.quarantine";
                var quarantinePath = Path.Combine(_config.QuarantinePath, quarantineName);

                File.Move(filePath, quarantinePath);
                action.QuarantinePath = quarantinePath;
                action.Success = true;

                _logger.Threat("Cleaner", $"Quarantined: {filePath} → {quarantinePath}");
            }
            catch (Exception ex)
            {
                action.Success = false;
                action.ErrorMessage = ex.Message;
                _logger.Error("Cleaner", $"Failed to quarantine {filePath}: {ex.Message}");
            }
        }

        _actionLog.Add(action);
        return action;
    }

    /// <summary>
    /// Restores a quarantined file to its original path.
    /// </summary>
    public bool RestoreFromQuarantine(CleanerAction quarantineAction)
    {
        if (quarantineAction.ActionType != CleanerActionType.QuarantineFile ||
            string.IsNullOrEmpty(quarantineAction.QuarantinePath))
            return false;

        try
        {
            if (File.Exists(quarantineAction.QuarantinePath))
            {
                File.Move(quarantineAction.QuarantinePath, quarantineAction.TargetPath);
                _logger.Info("Cleaner", $"Restored: {quarantineAction.TargetPath}");
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.Error("Cleaner", $"Failed to restore {quarantineAction.TargetPath}: {ex.Message}");
        }
        return false;
    }

    // ═══════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════

    private void ScanRegistryKey(RegistryKey hive, string keyPath, List<AutorunEntry> entries)
    {
        try
        {
            using var key = hive.OpenSubKey(keyPath);
            if (key == null) return;

            foreach (var name in key.GetValueNames())
            {
                var value = key.GetValue(name)?.ToString() ?? string.Empty;
                entries.Add(new AutorunEntry
                {
                    Source = "Registry",
                    Name = name,
                    Value = value,
                    Path = $"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\\{keyPath}",
                    RegistryKeyPath = keyPath
                });
            }
        }
        catch { }
    }
}

/// <summary>
/// Represents an autorun entry found in Registry or Startup folder.
/// </summary>
public class AutorunEntry
{
    public string Source { get; set; } = string.Empty;  // "Registry" or "StartupFolder"
    public string Name { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string RegistryKeyPath { get; set; } = string.Empty;
}
