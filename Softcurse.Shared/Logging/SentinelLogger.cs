using System.Collections.Concurrent;
using Softcurse.Shared.Models;

namespace Softcurse.Shared.Logging;

/// <summary>
/// Central logger for Softcurse Sentinel.
/// Uses buffered StreamWriter for efficient file I/O.
/// Thread-safe.
/// </summary>
public class SentinelLogger : IDisposable
{
    private readonly string _logDirectory;
    private readonly ConcurrentQueue<LogEntry> _buffer = new();
    private readonly int _maxBufferSize;
    private readonly object _fileLock = new();
    private StreamWriter? _writer;
    private string _currentLogDate;
    private bool _disposed;
    private readonly Timer _flushTimer;

    public SentinelLogger(string? logDirectory = null, int maxBufferSize = 500)
    {
        _maxBufferSize = maxBufferSize;
        _logDirectory = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SoftcurseSentinel", "Logs");
        Directory.CreateDirectory(_logDirectory);
        _currentLogDate = DateTime.Now.ToString("yyyy-MM-dd");
        OpenWriter();

        // Flush every 5 seconds
        _flushTimer = new Timer(_ => FlushWriter(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
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

        // Write to file (buffered)
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

    private void OpenWriter()
    {
        var logFilePath = Path.Combine(_logDirectory, $"sentinel_{_currentLogDate}.log");
        _writer = new StreamWriter(logFilePath, append: true) { AutoFlush = false };
    }

    private void WriteToFile(LogEntry entry)
    {
        if (_disposed) return;
        try
        {
            var line = $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [{entry.Level,-8}] [{entry.Source}] {entry.Message}";
            lock (_fileLock)
            {
                // Roll to new file at midnight
                var today = DateTime.Now.ToString("yyyy-MM-dd");
                if (today != _currentLogDate)
                {
                    _writer?.Flush();
                    _writer?.Dispose();
                    _currentLogDate = today;
                    OpenWriter();
                }
                _writer?.WriteLine(line);
            }
        }
        catch
        {
            // If file write fails, we still have the buffer.
        }
    }

    private void FlushWriter()
    {
        if (_disposed) return;
        lock (_fileLock)
        {
            try { _writer?.Flush(); } catch { }
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _flushTimer.Dispose();
        lock (_fileLock)
        {
            _writer?.Flush();
            _writer?.Dispose();
            _writer = null;
        }
        GC.SuppressFinalize(this);
    }
}
