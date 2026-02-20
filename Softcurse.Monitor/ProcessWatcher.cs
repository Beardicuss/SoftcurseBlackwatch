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
    private readonly SentinelLogger _logger;

    /// <summary>
    /// Fired when a new process is created. Provides PID and process name.
    /// </summary>
    public event EventHandler<ProcessCreatedEventArgs>? ProcessCreated;

    public ProcessWatcher(SentinelLogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Start watching for new process creation events.
    /// Requires admin privileges for Win32_ProcessStartTrace.
    /// </summary>
    public void Start()
    {
        try
        {
            _watcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            _logger.Info("ProcessWatcher", "WMI process watcher started");
        }
        catch (Exception ex)
        {
            _logger.Warning("ProcessWatcher",
                $"Could not start WMI watcher (admin required): {ex.Message}");
            // Fallback: we still have polling-based scanning in Core
        }
    }

    public void Stop()
    {
        try
        {
            _watcher?.Stop();
            _logger.Info("ProcessWatcher", "WMI process watcher stopped");
        }
        catch { }
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
        GC.SuppressFinalize(this);
    }
}

public class ProcessCreatedEventArgs : EventArgs
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}
