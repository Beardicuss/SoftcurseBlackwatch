using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Softcurse.Shared.Models;
using Softcurse.Shared.Security;

namespace Softcurse.Cleaner;

/// <summary>Durable append-only write-ahead journal for every response mutation.</summary>
public sealed class ActionJournal
{
    private readonly string _path;
    private readonly object _gate = new();
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = false };

    public ActionJournal(string? path = null)
    {
        _path = path ?? System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SoftcurseBlackwatch", "ActionJournal", "actions.jsonl");
        ProtectedLocalStorage.EnsurePrivateDirectory(
            System.IO.Path.GetDirectoryName(_path) ?? throw new InvalidDataException("Action journal path has no directory."));
        ProtectedLocalStorage.EnsurePrivateFile(_path);
    }

    public string Path => _path;

    public void Prepare(CleanerAction action)
    {
        action.Status = CleanerActionStatus.Prepared;
        Append(new ActionJournalRecord(action.ActionId, ActionJournalEvent.Prepared, DateTime.UtcNow, Snapshot(action)));
    }

    public void Complete(CleanerAction action)
    {
        action.CompletedUtc = DateTime.UtcNow;
        action.Status = action.Success ? CleanerActionStatus.Completed : CleanerActionStatus.Failed;
        Append(new ActionJournalRecord(
            action.ActionId,
            action.Success ? ActionJournalEvent.Completed : ActionJournalEvent.Failed,
            action.CompletedUtc.Value,
            Snapshot(action)));
    }

    public IReadOnlyList<CleanerAction> GetIncompleteActions()
    {
        var records = ReadRecords();
        var terminal = records.Where(record => record.Event is ActionJournalEvent.Completed or ActionJournalEvent.Failed)
            .Select(record => record.ActionId).ToHashSet(StringComparer.Ordinal);
        return records.Where(record => record.Event == ActionJournalEvent.Prepared && !terminal.Contains(record.ActionId))
            .GroupBy(record => record.ActionId, StringComparer.Ordinal)
            .Select(group => group.Last().Action.ToAction(group.Key, CleanerActionStatus.RecoveryRequired))
            .ToList();
    }

    public IReadOnlyList<ActionJournalRecord> ReadRecords()
        => ReadAndVerify().Records;

    private JournalReadResult ReadAndVerify()
    {
        if (!File.Exists(_path)) return new JournalReadResult([], "genesis", [], false);
        var lines = File.ReadAllLines(_path);
        var records = new List<ActionJournalRecord>(lines.Length);
        var validLines = new List<string>(lines.Length);
        var legacyLines = new List<string>();
        string? lastRecordHash = null;
        var chainStarted = false;
        var truncatedTail = false;
        for (var index = 0; index < lines.Length; index++)
        {
            if (string.IsNullOrWhiteSpace(lines[index])) continue;
            ActionJournalRecord record;
            try
            {
                record = JsonSerializer.Deserialize<ActionJournalRecord>(lines[index], JsonOptions)
                    ?? throw new JsonException("Null action journal record.");
            }
            catch (JsonException) when (index == lines.Length - 1)
            {
                // A power loss may leave only the final append truncated; prior flushed records remain recoverable.
                truncatedTail = true;
                break;
            }
            catch (JsonException ex)
            {
                throw new InvalidDataException($"Action journal is corrupt at line {index + 1}.", ex);
            }

            if (record.ChainVersion == 0)
            {
                if (chainStarted)
                    throw new InvalidDataException($"Unchained action journal record found after chain start at line {index + 1}.");
                legacyLines.Add(lines[index]);
            }
            else
            {
                if (record.ChainVersion != 1 ||
                    record.PreviousHash is null ||
                    record.RecordHash is null ||
                    record.RecordHash.Length != 64 ||
                    !record.RecordHash.All(Uri.IsHexDigit))
                    throw new InvalidDataException($"Action journal chain metadata is invalid at line {index + 1}.");
                chainStarted = true;
                var expectedPrevious = lastRecordHash ?? LegacyAnchor(legacyLines);
                if (!record.PreviousHash.Equals(expectedPrevious, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"Action journal chain link is invalid at line {index + 1}.");
                var expectedHash = ComputeRecordHash(record, expectedPrevious);
                if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(record.RecordHash),
                        Convert.FromHexString(expectedHash)))
                    throw new InvalidDataException($"Action journal record hash is invalid at line {index + 1}.");
                lastRecordHash = record.RecordHash.ToLowerInvariant();
            }
            records.Add(record);
            validLines.Add(lines[index]);
        }
        return new JournalReadResult(records, lastRecordHash ?? LegacyAnchor(legacyLines), validLines, truncatedTail);
    }

    private void Append(ActionJournalRecord record)
    {
        lock (_gate)
        {
            var state = ReadAndVerify();
            if (state.TruncatedTail)
                RewriteValidPrefix(state.ValidLines);
            var chained = record with
            {
                ChainVersion = 1,
                PreviousHash = state.NextPreviousHash
            };
            chained = chained with { RecordHash = ComputeRecordHash(chained, state.NextPreviousHash) };
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(chained, JsonOptions) + Environment.NewLine);
            using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
            ProtectedLocalStorage.EnsurePrivateFile(_path);
        }
    }

    private void RewriteValidPrefix(IReadOnlyList<string> lines)
    {
        var bytes = Encoding.UTF8.GetBytes(
            lines.Count == 0 ? string.Empty : string.Join(Environment.NewLine, lines) + Environment.NewLine);
        using var stream = new FileStream(_path, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static string LegacyAnchor(IEnumerable<string> legacyLines)
    {
        var content = string.Join("\n", legacyLines);
        if (content.Length == 0) return "genesis";
        return "legacy:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
    }

    private static string ComputeRecordHash(ActionJournalRecord record, string previousHash)
    {
        var payload = new ActionJournalPayload(record.ActionId, record.Event, record.TimestampUtc, record.Action);
        var canonical = previousHash + "\n" + JsonSerializer.Serialize(payload, JsonOptions);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static CleanerActionSnapshot Snapshot(CleanerAction action) => new(
        action.ActionType, action.TargetPid, action.TargetName, action.TargetPath,
        action.QuarantinePath, action.RegistryKey, action.RegistryValue, action.DryRun,
        action.Success, action.ErrorMessage);

    private sealed record JournalReadResult(
        IReadOnlyList<ActionJournalRecord> Records,
        string NextPreviousHash,
        IReadOnlyList<string> ValidLines,
        bool TruncatedTail);

    private sealed record ActionJournalPayload(
        string ActionId,
        ActionJournalEvent Event,
        DateTime TimestampUtc,
        CleanerActionSnapshot Action);
}

public enum ActionJournalEvent { Prepared, Completed, Failed }
public sealed record ActionJournalRecord(string ActionId, ActionJournalEvent Event, DateTime TimestampUtc, CleanerActionSnapshot Action)
{
    public int ChainVersion { get; init; }
    public string? PreviousHash { get; init; }
    public string? RecordHash { get; init; }
}
public sealed record CleanerActionSnapshot(
    CleanerActionType ActionType,
    int TargetPid,
    string TargetName,
    string TargetPath,
    string? QuarantinePath,
    string? RegistryKey,
    string? RegistryValue,
    bool DryRun,
    bool Success,
    string? ErrorMessage)
{
    public CleanerAction ToAction(string actionId, CleanerActionStatus status) => new()
    {
        ActionId = actionId,
        ActionType = ActionType,
        TargetPid = TargetPid,
        TargetName = TargetName,
        TargetPath = TargetPath,
        QuarantinePath = QuarantinePath,
        RegistryKey = RegistryKey,
        RegistryValue = RegistryValue,
        DryRun = DryRun,
        Success = Success,
        ErrorMessage = ErrorMessage,
        Status = status
    };
}
