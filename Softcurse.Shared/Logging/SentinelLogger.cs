using System.Collections.Concurrent;
using Softcurse.Shared.Models;

namespace Softcurse.Shared.Logging;

/// <summary>
/// Central logger for Softcurse Sentinel.
/// Writes to file and keeps an in-memory buffer for the UI.
/// Thread-safe.
/// </summary>
public class SentinelLogger : IDisposable
{
    private readonly string _logDirectory;
    private readonly string _logFilePath;
    private readonly ConcurrentQueue<LogEntry> _buffer = new();
    private readonly int _maxBufferSize;
    private readonly object _fileLock = new();
    private bool _disposed;

    public SentinelLogger(string? logDirectory = null, int maxBufferSize = 500)
    {
        _maxBufferSize = maxBufferSize;
        _logDirectory = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SoftcurseSentinel", "Logs");
        Directory.CreateDirectory(_logDirectory);
        _logFilePath = Path.Combine(_logDirectory, $"sentinel_{DateTime.Now:yyyy-MM-dd}.log");
    }

    public void Log(LogLevel level, string source, string message)
    {
        var entry = new LogEntry
        {
            Timestamp = DateTime.Now,
            Level = level,
            Source = source,
            Message = message
        };

        // Buffer for UI
        _buffer.Enqueue(entry);
        while (_buffer.Count > _maxBufferSize)
            _buffer.TryDequeue(out _);

        // Write to file
        WriteToFile(entry);
    }

    public void Debug(string source, string message) => Log(LogLevel.Debug, source, message);
    public void Info(string source, string message) => Log(LogLevel.Info, source, message);
    public void Warning(string source, string message) => Log(LogLevel.Warning, source, message);
    public void Threat(string source, string message) => Log(LogLevel.Threat, source, message);
    public void Error(string source, string message) => Log(LogLevel.Error, source, message);
    public void Critical(string source, string message) => Log(LogLevel.Critical, source, message);

    /// <summary>
    /// Gets all buffered log entries (for UI display).
    /// </summary>
    public IReadOnlyList<LogEntry> GetBuffer() => _buffer.ToArray();

    /// <summary>
    /// Gets entries filtered by minimum level.
    /// </summary>
    public IReadOnlyList<LogEntry> GetBuffer(LogLevel minLevel)
        => _buffer.Where(e => e.Level >= minLevel).ToArray();

    private void WriteToFile(LogEntry entry)
    {
        if (_disposed) return;
        try
        {
            var line = $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{entry.Level,-8}] [{entry.Source}] {entry.Message}";
            lock (_fileLock)
            {
                File.AppendAllText(_logFilePath, line + Environment.NewLine);
            }
        }
        catch
        {
            // If file write fails, we still have the buffer.
        }
    }

    public void Dispose()
    {
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
