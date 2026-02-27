using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using Softcurse.Cleaner;
using Softcurse.Core.Detection;
using Softcurse.Core.Scanning;
using Softcurse.Monitor;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.UI.ViewModels;

/// <summary>
/// MVVM ViewModel for MainWindow.
/// All heavy work runs on background threads, only UI updates on Dispatcher.
/// Exposes IsScanning + HasThreats for animation triggers.
/// </summary>
public class MainViewModel : INotifyPropertyChanged, IDisposable
{
    // ── Services ──
    private readonly SentinelLogger _logger;
    private readonly SentinelConfig _config;
    private readonly ProcessScanner _scanner;
    private readonly ThreatScorer _scorer;
    private readonly SystemMonitor _systemMonitor;
    private readonly ProcessWatcher _processWatcher;
    private readonly NetworkMonitor _networkMonitor;
    private readonly SentinelCleaner _cleaner;
    private readonly Dispatcher _dispatcher;

    // ── Timers ──
    private readonly DispatcherTimer _monitorTimer;
    private readonly DispatcherTimer _scanTimer;
    private readonly DispatcherTimer _logTimer;

    // ── Scan guard ──
    private volatile bool _scanRunning;
    private int _lastLogCount;

    // ── Observable Collections ──
    public ObservableCollection<ProcessInfo> Processes { get; } = new();
    public ObservableCollection<ThreatReport> Threats { get; } = new();
    public ObservableCollection<ConnectionInfo> Connections { get; } = new();
    public ObservableCollection<LogEntry> Logs { get; } = new();
    public ObservableCollection<float> CpuHistory { get; } = new();
    public ObservableCollection<float> RamHistory { get; } = new();

    // ── Dashboard Properties ──
    private float _cpuUsage;
    public float CpuUsage { get => _cpuUsage; set { _cpuUsage = value; OnPropertyChanged(); } }

    private float _ramUsage;
    public float RamUsage { get => _ramUsage; set { _ramUsage = value; OnPropertyChanged(); } }

    private float _ramUsedMB;
    public float RamUsedMB { get => _ramUsedMB; set { _ramUsedMB = value; OnPropertyChanged(); } }

    private float _ramTotalMB;
    public float RamTotalMB { get => _ramTotalMB; set { _ramTotalMB = value; OnPropertyChanged(); } }

    private int _processCount;
    public int ProcessCount { get => _processCount; set { _processCount = value; OnPropertyChanged(); } }

    private int _threatCount;
    public int ThreatCount
    {
        get => _threatCount;
        set
        {
            var old = _threatCount;
            _threatCount = value;
            OnPropertyChanged();
            // Update HasThreats for animation triggers
            HasThreats = value > 0;
            // Detect threat escalation (0 → 1+)
            if (old == 0 && value > 0)
                OnPropertyChanged(nameof(ThreatEscalated));
        }
    }

    private bool _hasThreats;
    public bool HasThreats { get => _hasThreats; set { _hasThreats = value; OnPropertyChanged(); } }

    /// <summary>Dummy property — fires PropertyChanged on 0→1+ threat transitions for animation triggers.</summary>
    public bool ThreatEscalated => ThreatCount > 0;

    private int _connectionCount;
    public int ConnectionCount { get => _connectionCount; set { _connectionCount = value; OnPropertyChanged(); } }

    private int _suspiciousConnectionCount;
    public int SuspiciousConnectionCount { get => _suspiciousConnectionCount; set { _suspiciousConnectionCount = value; OnPropertyChanged(); } }

    private bool _dryRunMode;
    public bool DryRunMode
    {
        get => _dryRunMode;
        set { _dryRunMode = value; _config.DryRunMode = value; _config.Save(); OnPropertyChanged(); }
    }

    // ── Scan State (for animations) ──
    private bool _isScanning;
    public bool IsScanning { get => _isScanning; set { _isScanning = value; OnPropertyChanged(); } }

    private string _scanButtonText = "● SCAN NOW";
    public string ScanButtonText { get => _scanButtonText; set { _scanButtonText = value; OnPropertyChanged(); } }

    private string _statusText = "INITIALIZING...";
    public string StatusText { get => _statusText; set { _statusText = value; OnPropertyChanged(); } }

    // ── Navigation ──
    private int _activeView;
    public int ActiveView { get => _activeView; set { _activeView = value; OnPropertyChanged(); } }

    // ── Settings Properties ──
    private bool _minimizeToTray;
    public bool MinimizeToTray
    {
        get => _minimizeToTray;
        set { _minimizeToTray = value; _config.MinimizeToTray = value; _config.Save(); OnPropertyChanged(); }
    }

    public ObservableCollection<string> WhitelistItems { get; } = new();

    private string _whitelistInput = string.Empty;
    public string WhitelistInput { get => _whitelistInput; set { _whitelistInput = value; OnPropertyChanged(); } }

    public bool WhitelistEmpty => WhitelistItems.Count == 0;

    public int CpuSpikeThreshold => _config.CpuSpikeThresholdPercent;
    public int CpuSpikeDuration => _config.CpuSpikeDurationSeconds;

    // ── Commands (MVVM) ──
    public ICommand NavigateCommand { get; }
    public ICommand ScanNowCommand { get; }
    public ICommand KillProcessCommand { get; }
    public ICommand AddWhitelistCommand { get; }
    public ICommand RemoveWhitelistCommand { get; }
    public ICommand BrowseWhitelistCommand { get; }

    public MainViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;

        // Init services
        _config = SentinelConfig.Load();
        _logger = new SentinelLogger();
        _scanner = new ProcessScanner(_logger);
        _scorer = new ThreatScorer(_logger, _config);
        _systemMonitor = new SystemMonitor(_logger);
        _processWatcher = new ProcessWatcher(_logger);
        _networkMonitor = new NetworkMonitor(_logger);
        _cleaner = new SentinelCleaner(_logger, _config);

        _dryRunMode = _config.DryRunMode;
        _minimizeToTray = _config.MinimizeToTray;

        // Load whitelist from config
        foreach (var item in _config.Whitelist)
            WhitelistItems.Add(item);

        // Commands
        NavigateCommand = new RelayCommand<int>(idx => ActiveView = idx);
        ScanNowCommand = new RelayCommand(_ => _ = RunFullScanAsync());
        KillProcessCommand = new RelayCommand<int>(pid => ExecuteKill(pid));
        AddWhitelistCommand = new RelayCommand(_ => ExecuteAddWhitelist());
        RemoveWhitelistCommand = new RelayCommand<string>(name => ExecuteRemoveWhitelist(name));
        BrowseWhitelistCommand = new RelayCommand(_ => ExecuteBrowseWhitelist());

        // Init history with zeros
        for (int i = 0; i < 60; i++)
        {
            CpuHistory.Add(0);
            RamHistory.Add(0);
        }

        // Monitor timer (2s) — CPU/RAM on background thread
        _monitorTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _monitorTimer.Tick += (_, _) => _ = OnMonitorTickAsync();
        _monitorTimer.Start();

        // Scan timer (5s) — Processes + Threats on background thread
        _scanTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _scanTimer.Tick += (_, _) => _ = RunFullScanAsync();
        _scanTimer.Start();

        // Log refresh timer (3s) — incremental update
        _logTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _logTimer.Tick += OnLogTick;
        _logTimer.Start();

        // Start WMI process watcher
        _processWatcher.ProcessCreated += OnNewProcessCreated;
        _processWatcher.Start();

        _logger.Info("Sentinel", "Softcurse Sentinel initialized");
        StatusText = "SYSTEM SECURE — NO THREATS DETECTED";
    }

    // ═══════════════════════════════════════════════
    // Timer Callbacks — async, off UI thread
    // ═══════════════════════════════════════════════

    private async Task OnMonitorTickAsync()
    {
        try
        {
            var snapshot = await Task.Run(() => _systemMonitor.GetSnapshot());

            CpuUsage = snapshot.CpuUsagePercent;
            RamUsage = snapshot.MemoryUsagePercent;
            RamUsedMB = snapshot.MemoryUsedMB;
            RamTotalMB = snapshot.MemoryTotalMB;

            CpuHistory.Add(snapshot.CpuUsagePercent);
            if (CpuHistory.Count > 60) CpuHistory.RemoveAt(0);

            RamHistory.Add(snapshot.MemoryUsagePercent);
            if (RamHistory.Count > 60) RamHistory.RemoveAt(0);

            OnPropertyChanged(nameof(CpuHistory));
            OnPropertyChanged(nameof(RamHistory));
        }
        catch { }
    }

    private void OnLogTick(object? sender, EventArgs e)
    {
        try
        {
            var entries = _logger.GetBuffer();
            var newCount = entries.Count;

            if (newCount != _lastLogCount)
            {
                var reversed = entries.Reverse().ToList();
                Logs.Clear();
                foreach (var entry in reversed)
                    Logs.Add(entry);
                _lastLogCount = newCount;
            }
        }
        catch { }
    }

    // ═══════════════════════════════════════════════
    // Scanning — runs on background thread
    // Lifecycle: status text changes step-by-step
    // ═══════════════════════════════════════════════

    private async Task RunFullScanAsync()
    {
        if (_scanRunning) return;
        _scanRunning = true;
        IsScanning = true;
        ScanButtonText = "⟳ SCANNING...";

        try
        {
            // Step 1: Enumerate
            StatusText = "ENUMERATING PROCESSES...";
            var procs = await Task.Run(() => _scanner.ScanAll());

            // Step 2: Analyze
            StatusText = "ANALYZING BEHAVIOR...";
            await Task.Run(() => _scorer.ScoreAll(procs));
            var reports = await Task.Run(() => _scorer.GenerateReports(procs, ThreatLevel.Low));

            // Step 3: Network
            StatusText = "CORRELATING NETWORK ACTIVITY...";
            var conns = await Task.Run(() => _networkMonitor.GetConnections());

            // Step 4: Update UI (incremental — avoids flicker)
            StatusText = "UPDATING RESULTS...";

            // Diff processes: update existing, add new, remove stale
            var procByPid = procs.ToDictionary(p => p.Pid);
            for (int i = Processes.Count - 1; i >= 0; i--)
            {
                if (!procByPid.ContainsKey(Processes[i].Pid))
                    Processes.RemoveAt(i);
            }
            var existingPids = new HashSet<int>(Processes.Select(p => p.Pid));
            foreach (var p in procs)
            {
                if (!existingPids.Contains(p.Pid))
                    Processes.Add(p);
            }
            ProcessCount = procs.Count;

            // Diff threats
            Threats.Clear();
            foreach (var r in reports)
                Threats.Add(r);
            ThreatCount = reports.Count(r => r.Score.Level >= ThreatLevel.Suspicious);

            // Diff connections
            Connections.Clear();
            foreach (var c in conns)
                Connections.Add(c);
            ConnectionCount = conns.Count;
            SuspiciousConnectionCount = conns.Count(c => c.IsSuspicious);

            // Final status
            StatusText = ThreatCount > 0
                ? $"⚠ {ThreatCount} THREATS DETECTED"
                : "SYSTEM SECURE — NO THREATS DETECTED";
        }
        catch (Exception ex)
        {
            _logger.Error("Sentinel", $"Scan failed: {ex.Message}");
            StatusText = "SCAN ERROR";
        }
        finally
        {
            _scanRunning = false;
            IsScanning = false;
            ScanButtonText = "● SCAN NOW";
        }
    }

    // ═══════════════════════════════════════════════
    // Actions
    // ═══════════════════════════════════════════════

    private void ExecuteKill(int pid)
    {
        var proc = Processes.FirstOrDefault(p => p.Pid == pid);
        if (proc == null) return;

        var result = _cleaner.KillProcess(pid, proc.Name, DryRunMode);
        if (result.Success)
            _ = RunFullScanAsync();
    }

    private void OnNewProcessCreated(object? sender, ProcessCreatedEventArgs e)
    {
        _logger.Info("ProcessWatcher", $"New process: {e.ProcessName} (PID {e.Pid})");

        // Instant threat scoring for new processes (closes the 5-second gap)
        Task.Run(() =>
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(e.Pid);
                var info = new ProcessInfo
                {
                    Pid = e.Pid,
                    Name = e.ProcessName,
                };
                try { info.FilePath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                try { info.MemoryMB = proc.WorkingSet64 / (1024.0 * 1024.0); } catch { }
                try { info.HasWindow = proc.MainWindowHandle != IntPtr.Zero; } catch { }
                proc.Dispose();

                _scorer.Score(info);

                if (info.Score.Level >= ThreatLevel.Suspicious)
                {
                    _dispatcher.Invoke(() =>
                    {
                        Threats.Add(new ThreatReport { Process = info, Score = info.Score });
                        ThreatCount = Threats.Count(t => t.Score.Level >= ThreatLevel.Suspicious);
                        StatusText = $"⚠ NEW THREAT: {info.Name} (Score {info.Score.Total})";
                    });
                }
            }
            catch { /* process already exited */ }
        });
    }

    /// <summary>Execute purge without MessageBox (called from JS confirm dialog)</summary>
    public void ExecutePurgeForced()
    {
        var criticals = Threats
            .Where(t => t.Score.Level >= ThreatLevel.High)
            .ToList();

        if (criticals.Count == 0) return;

        foreach (var threat in criticals)
        {
            _cleaner.KillProcess(threat.Process.Pid, threat.Process.Name, DryRunMode);
        }

        _logger.Threat("Sentinel", $"Purge executed: {criticals.Count} threats targeted");
        _ = RunFullScanAsync();
    }
    // ═══════════════════════════════════════════════
    // Whitelist Management
    // ═══════════════════════════════════════════════

    private void ExecuteAddWhitelist()
    {
        var entry = WhitelistInput?.Trim();
        if (string.IsNullOrEmpty(entry)) return;
        if (WhitelistItems.Contains(entry, StringComparer.OrdinalIgnoreCase)) return;

        WhitelistItems.Add(entry);
        _config.Whitelist = WhitelistItems.ToList();
        _config.Save();
        WhitelistInput = string.Empty;
        OnPropertyChanged(nameof(WhitelistEmpty));
        _logger.Info("Settings", $"Added to whitelist: {entry}");
    }

    private void ExecuteRemoveWhitelist(string name)
    {
        if (string.IsNullOrEmpty(name)) return;
        WhitelistItems.Remove(name);
        _config.Whitelist = WhitelistItems.ToList();
        _config.Save();
        OnPropertyChanged(nameof(WhitelistEmpty));
        _logger.Info("Settings", $"Removed from whitelist: {name}");
    }

    private void ExecuteBrowseWhitelist()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Executable to Whitelist",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog() == true)
        {
            var processName = System.IO.Path.GetFileNameWithoutExtension(dialog.FileName);
            if (!string.IsNullOrEmpty(processName) &&
                !WhitelistItems.Contains(processName, StringComparer.OrdinalIgnoreCase))
            {
                WhitelistItems.Add(processName);
                _config.Whitelist = WhitelistItems.ToList();
                _config.Save();
                OnPropertyChanged(nameof(WhitelistEmpty));
                _logger.Info("Settings", $"Added to whitelist via browse: {processName}");
            }
        }
    }

    // ═══════════════════════════════════════════════
    // INotifyPropertyChanged
    // ═══════════════════════════════════════════════

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void Dispose()
    {
        _monitorTimer.Stop();
        _scanTimer.Stop();
        _logTimer.Stop();
        _processWatcher.Dispose();
        _systemMonitor.Dispose();
        _logger.Dispose();
        GC.SuppressFinalize(this);
    }
}

// ═══════════════════════════════════════════════
// Command Implementations (MVVM)
// ═══════════════════════════════════════════════

public class RelayCommand<T> : ICommand
{
    private readonly Action<T> _execute;
    private readonly Func<T, bool>? _canExecute;

    public RelayCommand(Action<T> execute, Func<T, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) =>
        _canExecute == null || (_canExecute != null && parameter is T t && _canExecute(t));

    public void Execute(object? parameter)
    {
        if (parameter is T t)
            _execute(t);
        else if (parameter is string s && typeof(T) == typeof(int) && int.TryParse(s, out var i))
            _execute((T)(object)i);
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;

    public RelayCommand(Action<object?> execute) => _execute = execute;
    public bool CanExecute(object? parameter) => true;
    public void Execute(object? parameter) => _execute(parameter);

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
