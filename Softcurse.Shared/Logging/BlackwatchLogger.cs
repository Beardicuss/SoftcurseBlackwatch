using System.Collections.Concurrent;
using Softcurse.Shared.Models;
using Softcurse.Shared.Security;

namespace Softcurse.Shared.Logging;

/// <summary>
/// Central logger for Softcurse Blackwatch.
/// Uses buffered StreamWriter for efficient file I/O.
/// Thread-safe.
/// </summary>
public class BlackwatchLogger : IDisposable
{
    private static int _instanceSequence;
    private readonly string _logDirectory;
    private readonly string _sessionId;
    private readonly ConcurrentQueue<LogEntry> _buffer = new();
    private readonly int _maxBufferSize;
    private readonly TimeSpan _maxLogAge;
    private readonly long _maxTotalLogBytes;
    private readonly long _maxFileBytes;
    private readonly object _fileLock = new();
    private StreamWriter? _writer;
    private string _currentLogDate;
    private bool _disposed;
    private readonly Timer _flushTimer;
    public string LogDirectory => _logDirectory;

    public BlackwatchLogger(
        string? logDirectory = null,
        int maxBufferSize = 500,
        TimeSpan? maxLogAge = null,
        long maxTotalLogBytes = 20 * 1024 * 1024,
        long maxFileBytes = 5 * 1024 * 1024)
    {
        _maxBufferSize = maxBufferSize;
        _maxLogAge = maxLogAge ?? TimeSpan.FromDays(14);
        _maxTotalLogBytes = maxTotalLogBytes;
        _maxFileBytes = maxFileBytes;
        _sessionId = $"{Environment.ProcessId}_{Interlocked.Increment(ref _instanceSequence):D3}";
        _logDirectory = logDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SoftcurseBlackwatch", "Logs");
        ProtectedLocalStorage.EnsurePrivateDirectory(_logDirectory);
        LogRetentionPolicy.Apply(_logDirectory, _maxLogAge, _maxTotalLogBytes, DateTime.UtcNow);
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
            Source = LogRedactor.Redact(source),
            Message = LogRedactor.Redact(message)
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

    public void Flush() => FlushWriter();

    private void OpenWriter()
    {
        var logFilePath = SelectWritableLogPath();
        _writer = new StreamWriter(logFilePath, append: true) { AutoFlush = false };
        ProtectedLocalStorage.EnsurePrivateFile(logFilePath);
    }

    private string SelectWritableLogPath()
    {
        for (var index = 0; index < 10_000; index++)
        {
            var suffix = index == 0 ? string.Empty : $"_{index:D3}";
            var candidate = Path.Combine(_logDirectory, $"blackwatch_{_currentLogDate}_{_sessionId}{suffix}.log");
            if (!File.Exists(candidate) || new FileInfo(candidate).Length < _maxFileBytes) return candidate;
        }
        throw new IOException("Blackwatch log rotation exhausted the daily file sequence.");
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
                    LogRetentionPolicy.Apply(_logDirectory, _maxLogAge, _maxTotalLogBytes, DateTime.UtcNow);
                    OpenWriter();
                }
                else if (_writer?.BaseStream.Length >= _maxFileBytes)
                {
                    _writer.Flush();
                    _writer.Dispose();
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
