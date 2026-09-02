using System.Diagnostics;
using System.Management;
using Softcurse.Shared.Logging;

namespace Softcurse.Monitor;

/// <summary>
/// WMI-based real-time process creation watcher.
/// Fires an event whenever a new process starts on the system.
/// Uses Win32_ProcessStartTrace — sees everything being born.
/// </summary>
public class ProcessWatcher : IDisposable
{
    private ManagementEventWatcher? _watcher;
    private Timer? _fallbackTimer;
    private readonly object _processIdsLock = new();
    private HashSet<int> _knownProcessIds = [];
    private int _pollInProgress;
    private readonly BlackwatchLogger _logger;
    public bool IsUsingPollingFallback { get; private set; }

    /// <summary>
    /// Fired when a new process is created. Provides PID and process name.
    /// </summary>
    public event EventHandler<ProcessCreatedEventArgs>? ProcessCreated;

    public ProcessWatcher(BlackwatchLogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Start watching for new process creation events.
    /// Uses WMI when available and a non-admin polling fallback otherwise.
    /// </summary>
    public void Start()
    {
        try
        {
            _knownProcessIds = SnapshotProcessIds();
            _watcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            _logger.Info("ProcessWatcher", "WMI process watcher started");
        }
        catch (Exception ex)
        {
            _watcher?.Dispose();
            _watcher = null;
            IsUsingPollingFallback = true;
            _fallbackTimer = new Timer(PollForNewProcesses, null, TimeSpan.Zero, TimeSpan.FromSeconds(1));
            _logger.Warning("ProcessWatcher",
                $"WMI process events are unavailable; using non-admin polling fallback: {ex.Message}");
        }
    }

    public void Stop()
    {
        try
        {
            _watcher?.Stop();
            _fallbackTimer?.Dispose();
            _fallbackTimer = null;
            _logger.Info("ProcessWatcher", IsUsingPollingFallback
                ? "Process polling fallback stopped"
                : "WMI process watcher stopped");
        }
        catch { }
    }

    private void PollForNewProcesses(object? state)
    {
        if (Interlocked.Exchange(ref _pollInProgress, 1) != 0) return;
        try
        {
            var current = SnapshotProcessIds();
            int[] created;
            lock (_processIdsLock)
            {
                created = current.Except(_knownProcessIds).ToArray();
                _knownProcessIds = current;
            }

            foreach (var pid in created)
            {
                string name;
                try
                {
                    using var process = Process.GetProcessById(pid);
                    name = process.ProcessName;
                }
                catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
                {
                    continue;
                }

                ProcessCreated?.Invoke(this, new ProcessCreatedEventArgs
                {
                    Pid = pid,
                    ProcessName = name,
                    Timestamp = DateTime.Now,
                });
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("ProcessWatcher", $"Polling fallback failed: {ex.Message}");
        }
        finally
        {
            Volatile.Write(ref _pollInProgress, 0);
        }
    }

    private static HashSet<int> SnapshotProcessIds()
    {
        var ids = new HashSet<int>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try { ids.Add(process.Id); }
                catch (InvalidOperationException) { }
            }
        }
        return ids;
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var pid = Convert.ToInt32(e.NewEvent.Properties["ProcessID"].Value);
            var name = e.NewEvent.Properties["ProcessName"]?.Value?.ToString() ?? "unknown";

            _logger.Debug("ProcessWatcher", $"New process: {name} (PID {pid})");

            ProcessCreated?.Invoke(this, new ProcessCreatedEventArgs
            {
                Pid = pid,
                ProcessName = name,
                Timestamp = DateTime.Now
            });
        }
        catch (Exception ex)
        {
            _logger.Warning("ProcessWatcher", $"Error handling process event: {ex.Message}");
        }
    }

    public void Dispose()
    {
        Stop();
        _watcher?.Dispose();
        _fallbackTimer?.Dispose();
        GC.SuppressFinalize(this);
    }
}

public class ProcessCreatedEventArgs : EventArgs
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}
