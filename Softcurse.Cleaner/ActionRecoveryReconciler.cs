using System.Security.Cryptography;
using System.Text.Json;
using Softcurse.Shared.Models;

namespace Softcurse.Cleaner;

/// <summary>Reconciles interrupted file transactions conservatively and never mutates target files.</summary>
public sealed class ActionRecoveryReconciler(ActionJournal journal)
{
    public IReadOnlyList<ActionRecoveryResult> Reconcile()
    {
        var results = new List<ActionRecoveryResult>();
        foreach (var action in journal.GetIncompleteActions())
        {
            var result = action.ActionType switch
            {
                CleanerActionType.QuarantineFile => ReconcileQuarantine(action),
                CleanerActionType.RestoreQuarantine => ReconcileRestore(action),
                _ => new(action, RecoveryDisposition.ManualReview, "Mutation type cannot be proven from filesystem state.")
            };
            results.Add(result);
            if (result.Disposition is RecoveryDisposition.Completed or RecoveryDisposition.NotStarted)
            {
                action.Success = result.Disposition == RecoveryDisposition.Completed;
                action.ErrorMessage = result.Message;
                journal.Complete(action);
            }
        }
        return results;
    }

    private static ActionRecoveryResult ReconcileQuarantine(CleanerAction action)
    {
        if (string.IsNullOrWhiteSpace(action.TargetPath) || string.IsNullOrWhiteSpace(action.QuarantinePath))
            return new(action, RecoveryDisposition.ManualReview, "Journal lacks quarantine paths.");
        var sourceExists = File.Exists(action.TargetPath);
        var quarantineExists = File.Exists(action.QuarantinePath);
        if (sourceExists && !quarantineExists)
            return new(action, RecoveryDisposition.NotStarted, "Prepared quarantine did not move the source file.");
        if (!sourceExists && quarantineExists)
            return ValidateManifest(action, action.QuarantinePath, RecoveryDisposition.Completed, "Quarantine move completed before interruption.");
        return new(action, RecoveryDisposition.ManualReview,
            sourceExists ? "Both source and quarantine files exist." : "Both source and quarantine files are missing.");
    }

    private static ActionRecoveryResult ReconcileRestore(CleanerAction action)
    {
        if (string.IsNullOrWhiteSpace(action.TargetPath) || string.IsNullOrWhiteSpace(action.QuarantinePath))
            return new(action, RecoveryDisposition.ManualReview, "Journal lacks restore paths.");
        var targetExists = File.Exists(action.TargetPath);
        var quarantineExists = File.Exists(action.QuarantinePath);
        if (!targetExists && quarantineExists)
            return new(action, RecoveryDisposition.NotStarted, "Prepared restore did not move the quarantined file.");
        if (targetExists && !quarantineExists)
            return ValidateManifest(action, action.TargetPath, RecoveryDisposition.Completed, "Restore move completed before interruption.");
        return new(action, RecoveryDisposition.ManualReview,
            targetExists ? "Both restore target and quarantine files exist." : "Both restore target and quarantine files are missing.");
    }

    private static ActionRecoveryResult ValidateManifest(CleanerAction action, string contentPath, RecoveryDisposition success, string message)
    {
        try
        {
            var manifestPath = action.QuarantinePath + ".manifest.json";
            var manifest = JsonSerializer.Deserialize<QuarantineManifest>(File.ReadAllText(manifestPath))
                ?? throw new InvalidDataException("Manifest is empty.");
            if (!Path.GetFullPath(manifest.OriginalPath).Equals(Path.GetFullPath(action.TargetPath), StringComparison.OrdinalIgnoreCase) ||
                !Path.GetFullPath(manifest.QuarantinePath).Equals(Path.GetFullPath(action.QuarantinePath!), StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Manifest paths do not match the journal.");
            using var stream = File.OpenRead(contentPath);
            var hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            if (!hash.Equals(manifest.OriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Content hash does not match the manifest.");
            return new(action, success, message);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            return new(action, RecoveryDisposition.ManualReview, $"Integrity could not be proven: {ex.Message}");
        }
    }
}

public enum RecoveryDisposition { Completed, NotStarted, ManualReview }
public sealed record ActionRecoveryResult(CleanerAction Action, RecoveryDisposition Disposition, string Message);
