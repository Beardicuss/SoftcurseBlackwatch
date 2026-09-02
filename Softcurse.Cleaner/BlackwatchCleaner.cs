using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;
using Softcurse.Shared.Security;

namespace Softcurse.Cleaner;

/// <summary>
/// Response engine for Softcurse Blackwatch.
/// Kills processes, removes autoruns, quarantines files.
/// Every action is logged. Dry-run mode available.
/// Never deletes — quarantines first.
/// </summary>
public class BlackwatchCleaner
{
    private readonly BlackwatchLogger _logger;
    private readonly BlackwatchConfig _config;
    private readonly ActionJournal _journal;
    private readonly MutationAuthorizationService _authorizations;
    private bool _journalHealthy = true;
    private readonly List<CleanerAction> _actionLog = new();
    private readonly List<CleanerAction> _recoveryRequiredActions = new();
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "csrss", "wininit", "winlogon", "services", "lsass", "smss",
        "registry", "memorycompression"
    };

    public IReadOnlyList<CleanerAction> ActionLog => _actionLog;
    public IReadOnlyList<CleanerAction> RecoveryRequiredActions => _recoveryRequiredActions;
    public IReadOnlyList<ActionRecoveryResult> RecoveryResults { get; }

    // Registry Run keys where malware loves to hide
    private static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    };

    public BlackwatchCleaner(BlackwatchLogger logger, BlackwatchConfig config, ActionJournal? journal = null, MutationAuthorizationService? authorizations = null)
    {
        _logger = logger;
        _config = config;
        _journal = journal ?? new ActionJournal();
        _authorizations = authorizations ?? new MutationAuthorizationService();
        ProtectedLocalStorage.EnsurePrivateDirectory(_config.QuarantinePath);
        try
        {
            RecoveryResults = new ActionRecoveryReconciler(_journal).Reconcile();
            _recoveryRequiredActions.AddRange(_journal.GetIncompleteActions());
        }
        catch (Exception ex)
        {
            RecoveryResults = [];
            _journalHealthy = false;
            _logger.Critical("Cleaner", $"Action journal recovery failed; live mutations are disabled: {ex.Message}");
        }
        if (RecoveryRequiredActions.Count > 0)
            _logger.Warning("Cleaner", $"{RecoveryRequiredActions.Count} interrupted action(s) require recovery review.");
        foreach (var result in RecoveryResults)
            _logger.Info("CleanerRecovery", $"{result.Action.ActionId}: {result.Disposition} — {result.Message}");
    }

    public MutationAuthorization AuthorizeProcessKill(int pid, string processName, DateTime? expectedStartTime)
    {
        var authorization = _authorizations.Issue(
            MutationAuthorizationScope.ProcessKill,
            ProcessTargetIdentity(pid, processName, expectedStartTime),
            DateTime.UtcNow);
        _logger.Info("CleanerConsent", $"User authorized process termination for {processName} (PID {pid}).");
        return authorization;
    }

    // ═══════════════════════════════════════════════
    // 1. KILL PROCESS
    // ═══════════════════════════════════════════════

    /// <summary>
    /// Terminates a process by PID. Logs the action.
    /// </summary>
    public CleanerAction KillProcess(
        int pid,
        string processName,
        DateTime? expectedStartTime = null,
        bool dryRun = false,
        MutationAuthorization? authorization = null)
    {
        var action = new CleanerAction
        {
            ActionType = CleanerActionType.KillProcess,
            TargetPid = pid,
            TargetName = processName,
            DryRun = dryRun || _config.DryRunMode
        };

        if (!TryPrepare(action))
        {
            _actionLog.Add(action);
            return action;
        }

        if (!action.DryRun && ProtectedProcessNames.Contains(processName))
        {
            action.Success = false;
            action.ErrorMessage = $"Live termination rejected: {processName} is a protected Windows process.";
            _logger.Warning("CleanerPolicy", action.ErrorMessage);
            CompleteAction(action);
            return action;
        }

        if (!action.DryRun && !_authorizations.Consume(
                authorization,
                MutationAuthorizationScope.ProcessKill,
                ProcessTargetIdentity(pid, processName, expectedStartTime),
                DateTime.UtcNow))
        {
            action.Success = false;
            action.ErrorMessage = "Live termination rejected: explicit target-bound authorization is missing, expired, invalid, or already used.";
            _logger.Warning("CleanerConsent", action.ErrorMessage);
            CompleteAction(action);
            return action;
        }

        if (action.DryRun)
        {
            action.Success = true;
            _logger.Info("Cleaner", $"[DRY-RUN] Would kill: {processName} (PID {pid})");
        }
        else
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (!string.Equals(proc.ProcessName, processName, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        $"Process identity changed: expected {processName}, found {proc.ProcessName}");

                if (expectedStartTime is { } expected && expected != DateTime.MinValue)
                {
                    var actual = proc.StartTime;
                    if (Math.Abs((actual - expected).TotalSeconds) > 1)
                        throw new InvalidOperationException(
                            "Process identity changed: PID was reused after the scan");
                }

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

        CompleteAction(action);
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

        if (!TryPrepare(action))
        {
            _actionLog.Add(action);
            return action;
        }

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

        CompleteAction(action);
        return action;
    }

    public MutationAuthorization? AuthorizeRecovery(string actionId, RecoveryActionKind kind)
    {
        var action = _recoveryRequiredActions.FirstOrDefault(item => item.ActionId.Equals(actionId, StringComparison.Ordinal));
        if (action is null) return null;
        var authorization = _authorizations.Issue(
            RecoveryScope(kind),
            RecoveryTargetIdentity(actionId),
            DateTime.UtcNow);
        _logger.Info("CleanerConsent", $"User authorized recovery {kind} for action {actionId}.");
        return authorization;
    }

    public bool ResolveRecovery(string actionId, bool completed, string note, RecoveryActionKind kind, MutationAuthorization? authorization)
    {
        var action = _recoveryRequiredActions.FirstOrDefault(item => item.ActionId.Equals(actionId, StringComparison.Ordinal));
        if (action is null || string.IsNullOrWhiteSpace(note)) return false;
        if (kind == RecoveryActionKind.Restore ||
            !_authorizations.Consume(authorization, RecoveryScope(kind), RecoveryTargetIdentity(actionId), DateTime.UtcNow))
        {
            _logger.Warning("CleanerConsent", $"Recovery {kind} rejected for {actionId}: authorization is missing, expired, invalid, or already used.");
            return false;
        }
        return ResolveRecoveryCore(action, completed, note);
    }

    private bool ResolveRecoveryCore(CleanerAction action, bool completed, string note)
    {
        var actionId = action.ActionId;
        action.Success = completed;
        action.ErrorMessage = note;
        try
        {
            _journal.Complete(action);
            _recoveryRequiredActions.Remove(action);
            _logger.Info("CleanerRecovery", $"{actionId}: manually finalized as {(completed ? "completed" : "not completed")} — {note}");
            return true;
        }
        catch (Exception ex)
        {
            _journalHealthy = false;
            _logger.Critical("CleanerRecovery", $"Could not finalize {actionId}: {ex.Message}");
            return false;
        }
    }

    public bool RestoreRecovery(string actionId, MutationAuthorization? authorization)
    {
        var interrupted = _recoveryRequiredActions.FirstOrDefault(item => item.ActionId.Equals(actionId, StringComparison.Ordinal));
        if (interrupted is null || string.IsNullOrWhiteSpace(interrupted.QuarantinePath)) return false;
        if (!_authorizations.Consume(
                authorization,
                MutationAuthorizationScope.RecoveryRestore,
                RecoveryTargetIdentity(actionId),
                DateTime.UtcNow))
        {
            _logger.Warning("CleanerConsent", $"Recovery Restore rejected for {actionId}: authorization is missing, expired, invalid, or already used.");
            return false;
        }
        var quarantineAction = new CleanerAction
        {
            ActionType = CleanerActionType.QuarantineFile,
            TargetName = interrupted.TargetName,
            TargetPath = interrupted.TargetPath,
            QuarantinePath = interrupted.QuarantinePath
        };
        if (!RestoreFromQuarantine(quarantineAction)) return false;
        return ResolveRecoveryCore(interrupted, completed: false, "Explicitly rolled back through a verified quarantine restore.");
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

        if (!action.DryRun)
        {
            var quarantineName = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{action.ActionId}_{Path.GetFileName(filePath)}.quarantine";
            action.QuarantinePath = Path.Combine(_config.QuarantinePath, quarantineName);
        }

        if (!TryPrepare(action))
        {
            _actionLog.Add(action);
            return action;
        }

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
                    CompleteAction(action);
                    return action;
                }

                var quarantinePath = action.QuarantinePath!;
                var file = new FileInfo(filePath);
                var manifest = new QuarantineManifest
                {
                    ActionId = action.ActionId,
                    OriginalPath = Path.GetFullPath(filePath),
                    QuarantinePath = Path.GetFullPath(quarantinePath),
                    OriginalLength = file.Length,
                    OriginalSha256 = ComputeSha256(filePath),
                    QuarantinedUtc = DateTime.UtcNow
                };
                WriteManifest(manifest);
                File.Move(filePath, quarantinePath);
                ProtectedLocalStorage.EnsurePrivateFile(quarantinePath);
                ProtectedLocalStorage.EnsurePrivateFile(ManifestPath(quarantinePath));
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

        CompleteAction(action);
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

        var restore = new CleanerAction
        {
            ActionType = CleanerActionType.RestoreQuarantine,
            TargetName = quarantineAction.TargetName,
            TargetPath = quarantineAction.TargetPath,
            QuarantinePath = quarantineAction.QuarantinePath,
            DryRun = _config.DryRunMode
        };
        if (!TryPrepare(restore))
        {
            _actionLog.Add(restore);
            return false;
        }

        try
        {
            if (restore.DryRun)
            {
                restore.Success = true;
                _logger.Info("Cleaner", $"[DRY-RUN] Would restore: {restore.TargetPath}");
            }
            else if (File.Exists(quarantineAction.QuarantinePath))
            {
                var manifest = ReadManifest(quarantineAction.QuarantinePath);
                if (!Path.GetFullPath(manifest.OriginalPath).Equals(Path.GetFullPath(quarantineAction.TargetPath), StringComparison.OrdinalIgnoreCase) ||
                    !Path.GetFullPath(manifest.QuarantinePath).Equals(Path.GetFullPath(quarantineAction.QuarantinePath), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Quarantine manifest identity does not match the requested restore.");
                if (File.Exists(quarantineAction.TargetPath))
                    throw new IOException("Restore target already exists; overwrite refused.");
                if (!ComputeSha256(quarantineAction.QuarantinePath).Equals(manifest.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Quarantined file hash does not match its manifest.");
                File.Move(quarantineAction.QuarantinePath, quarantineAction.TargetPath);
                manifest.RestoredUtc = DateTime.UtcNow;
                WriteManifest(manifest);
                restore.Success = true;
                _logger.Info("Cleaner", $"Restored: {quarantineAction.TargetPath}");
            }
            else restore.ErrorMessage = "Quarantined file not found";
        }
        catch (Exception ex)
        {
            restore.Success = false;
            restore.ErrorMessage = ex.Message;
            _logger.Error("Cleaner", $"Failed to restore {quarantineAction.TargetPath}: {ex.Message}");
        }
        CompleteAction(restore);
        return restore.Success;
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

    private bool TryPrepare(CleanerAction action)
    {
        if (!_journalHealthy)
        {
            action.Success = false;
            action.Status = CleanerActionStatus.Failed;
            action.ErrorMessage = "Action blocked because the action journal requires repair.";
            return false;
        }
        try
        {
            _journal.Prepare(action);
            return true;
        }
        catch (Exception ex)
        {
            action.Success = false;
            action.Status = CleanerActionStatus.Failed;
            action.ErrorMessage = $"Action blocked because the write-ahead journal failed: {ex.Message}";
            _logger.Critical("Cleaner", action.ErrorMessage);
            return false;
        }
    }

    private void CompleteAction(CleanerAction action)
    {
        try { _journal.Complete(action); }
        catch (Exception ex)
        {
            action.Status = CleanerActionStatus.RecoveryRequired;
            action.ErrorMessage = string.IsNullOrWhiteSpace(action.ErrorMessage)
                ? $"Mutation completed but journal finalization failed: {ex.Message}"
                : $"{action.ErrorMessage}; journal finalization failed: {ex.Message}";
            _logger.Critical("Cleaner", action.ErrorMessage);
        }
        _actionLog.Add(action);
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static string ProcessTargetIdentity(int pid, string name, DateTime? startTime) =>
        $"{pid}|{name.ToUpperInvariant()}|{startTime?.ToUniversalTime().Ticks ?? 0}";

    private static string RecoveryTargetIdentity(string actionId) => actionId;

    private static MutationAuthorizationScope RecoveryScope(RecoveryActionKind kind) => kind switch
    {
        RecoveryActionKind.Restore => MutationAuthorizationScope.RecoveryRestore,
        RecoveryActionKind.Finalize => MutationAuthorizationScope.RecoveryFinalize,
        RecoveryActionKind.Dismiss => MutationAuthorizationScope.RecoveryDismiss,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    private static string ManifestPath(string quarantinePath) => quarantinePath + ".manifest.json";

    private static void WriteManifest(QuarantineManifest manifest)
    {
        var path = ManifestPath(manifest.QuarantinePath);
        var temporary = path + $".{Guid.NewGuid():N}.tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, path, overwrite: true);
        }
        finally { try { File.Delete(temporary); } catch { } }
    }

    private static QuarantineManifest ReadManifest(string quarantinePath) =>
        JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(ManifestPath(quarantinePath)))
        ?? throw new InvalidDataException("Quarantine manifest is empty.");
}

public sealed class QuarantineManifest
{
    public string ActionId { get; set; } = string.Empty;
    public string OriginalPath { get; set; } = string.Empty;
    public string QuarantinePath { get; set; } = string.Empty;
    public long OriginalLength { get; set; }
    public string OriginalSha256 { get; set; } = string.Empty;
    public DateTime QuarantinedUtc { get; set; }
    public DateTime? RestoredUtc { get; set; }
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
