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
using Softcurse.Shared.Security;

namespace Softcurse.UI.ViewModels;

/// <summary>
/// MVVM ViewModel for MainWindow.
/// All heavy work runs on background threads, only UI updates on Dispatcher.
/// Exposes IsScanning + HasThreats for animation triggers.
/// </summary>
public class MainViewModel : INotifyPropertyChanged, IDisposable
{
    // ── Services ──
    private readonly BlackwatchLogger _logger;
    private readonly BlackwatchConfig _config;
    private readonly ProcessScanner _scanner;
    private readonly ThreatScorer _scorer;
    private readonly SystemMonitor _systemMonitor;
    private readonly ProcessWatcher _processWatcher;
    private readonly NetworkMonitor _networkMonitor;
    private readonly BlackwatchCleaner _cleaner;
    private readonly Dispatcher _dispatcher;

    // ── Work guards / lifetime ──
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private readonly SemaphoreSlim _monitorGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly List<Task> _recurringTasks = new();
    private DateTime _lastLogTimestamp = DateTime.MinValue;
    private bool _disposed;

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
        set { _dryRunMode = value; _config.DryRunMode = value; SaveConfig(); OnPropertyChanged(); }
    }

    // ── Scan State (for animations) ──
    private bool _isScanning;
    public bool IsScanning { get => _isScanning; set { _isScanning = value; OnPropertyChanged(); } }

    private string _scanButtonText = "● SCAN NOW";
    public string ScanButtonText { get => _scanButtonText; set { _scanButtonText = value; OnPropertyChanged(); } }

    private string _statusText = "INITIALIZING...";
    public string StatusText { get => _statusText; set { _statusText = value; OnPropertyChanged(); } }

    private TelemetryHealthLevel _healthLevel = TelemetryHealthLevel.Error;
    public TelemetryHealthLevel HealthLevel { get => _healthLevel; private set { _healthLevel = value; OnPropertyChanged(); } }

    private string _healthMessage = "Telemetry has not completed yet.";
    public string HealthMessage { get => _healthMessage; private set { _healthMessage = value; OnPropertyChanged(); } }

    private DateTime? _lastSuccessfulScanUtc;
    public DateTime? LastSuccessfulScanUtc { get => _lastSuccessfulScanUtc; private set { _lastSuccessfulScanUtc = value; OnPropertyChanged(); } }

    // ── Navigation ──
    private int _activeView;
    public int ActiveView { get => _activeView; set { _activeView = value; OnPropertyChanged(); } }

    // ── Settings Properties ──
    private bool _minimizeToTray;
    public bool MinimizeToTray
    {
        get => _minimizeToTray;
        set { _minimizeToTray = value; _config.MinimizeToTray = value; SaveConfig(); OnPropertyChanged(); }
    }

    public ObservableCollection<string> WhitelistItems { get; } = new();
    public IReadOnlyList<TrustedApplication> TrustedApplications => _config.TrustedApplications;

    public bool WhitelistEmpty => WhitelistItems.Count == 0;

    public int CpuSpikeThreshold => _config.CpuSpikeThresholdPercent;
    public int CpuSpikeDuration => _config.CpuSpikeDurationSeconds;
    public IReadOnlyList<CleanerAction> RecoveryActions => _cleaner.RecoveryRequiredActions;

    // ── Commands (MVVM) ──
    public ICommand NavigateCommand { get; }
    public ICommand ScanNowCommand { get; }
    public ICommand KillProcessCommand { get; }
    public ICommand RemoveWhitelistCommand { get; }

    public MainViewModel()
    {
        _dispatcher = Dispatcher.CurrentDispatcher;

        // Init services
        _config = BlackwatchConfig.Load();
        _logger = new BlackwatchLogger();
        _scanner = new ProcessScanner(_logger);
        _scorer = new ThreatScorer(_logger, _config);
        _systemMonitor = new SystemMonitor(_logger);
        _processWatcher = new ProcessWatcher(_logger);
        _networkMonitor = new NetworkMonitor(_logger);
        _cleaner = new BlackwatchCleaner(_logger, _config);

        if (BlackwatchConfig.LastPersistenceError is { } configError)
            _logger.Warning("Config", configError);

        _dryRunMode = _config.DryRunMode;
        _minimizeToTray = _config.MinimizeToTray;

        // Load whitelist from config
        foreach (var item in _config.Whitelist)
            WhitelistItems.Add(item);

        // Commands
        NavigateCommand = new RelayCommand<int>(idx => ActiveView = idx);
        ScanNowCommand = new RelayCommand(_ => _ = RunFullScanAsync());
        KillProcessCommand = new RelayCommand<int>(pid => ExecuteKill(pid));
        RemoveWhitelistCommand = new RelayCommand<string>(name => ExecuteRemoveWhitelist(name));

        // Init history with zeros
        for (int i = 0; i < 60; i++)
        {
            CpuHistory.Add(0);
            RamHistory.Add(0);
        }

        _recurringTasks.Add(RunPeriodicAsync(TimeSpan.FromSeconds(2), OnMonitorTickAsync));
        _recurringTasks.Add(RunPeriodicAsync(TimeSpan.FromSeconds(5), RunFullScanAsync));
        _recurringTasks.Add(RunPeriodicAsync(TimeSpan.FromSeconds(3), RefreshLogsAsync));

        // Start WMI process watcher
        _processWatcher.ProcessCreated += OnNewProcessCreated;
        _processWatcher.Start();

        _logger.Info("Blackwatch", "Softcurse Blackwatch initialized");
        StatusText = "INITIALIZING MONITORING...";
        _ = RunFullScanAsync();
    }

    // ═══════════════════════════════════════════════
    // Lifetime-bound recurring work
    // ═══════════════════════════════════════════════

    private async Task RunPeriodicAsync(TimeSpan interval, Func<Task> callback)
    {
        using var timer = new PeriodicTimer(interval);
        try
        {
            while (await timer.WaitForNextTickAsync(_lifetime.Token).ConfigureAwait(false))
                await _dispatcher.InvokeAsync(callback).Task.Unwrap().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.Error("Lifecycle", $"Recurring task stopped unexpectedly: {ex.Message}");
        }
    }

    private async Task OnMonitorTickAsync()
    {
        if (!await _monitorGate.WaitAsync(0)) return;
        try
        {
            var snapshot = await Task.Run(() => _systemMonitor.GetSnapshot(_lifetime.Token), _lifetime.Token);

            CpuUsage = snapshot.CpuUsagePercent;
            RamUsage = snapshot.MemoryUsagePercent;
            RamUsedMB = snapshot.MemoryUsedMB;
            RamTotalMB = snapshot.MemoryTotalMB;
            var previousHealth = HealthLevel;
            ApplyOverallHealth();
            if (previousHealth != HealthLevel && !IsScanning)
            {
                StatusText = HealthLevel == TelemetryHealthLevel.Healthy
                    ? ThreatCount > 0 ? $"⚠ {ThreatCount} SUSPICIOUS ITEMS DETECTED" : "NO SUSPICIOUS ACTIVITY DETECTED BY BLACKWATCH"
                    : $"⚠ MONITORING {HealthLevel.ToString().ToUpperInvariant()} — RESULTS MAY BE INCOMPLETE";
            }

            CpuHistory.Add(snapshot.CpuUsagePercent);
            if (CpuHistory.Count > 60) CpuHistory.RemoveAt(0);

            RamHistory.Add(snapshot.MemoryUsagePercent);
            if (RamHistory.Count > 60) RamHistory.RemoveAt(0);

            OnPropertyChanged(nameof(CpuHistory));
            OnPropertyChanged(nameof(RamHistory));
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.Warning("SystemMonitor", $"Monitor update failed: {ex.Message}");
            ApplyHealth(TelemetryHealth.Error($"System telemetry failed: {ex.Message}"));
        }
        finally
        {
            _monitorGate.Release();
        }
    }

    private Task RefreshLogsAsync()
    {
        try
        {
            var entries = _logger.GetBuffer();
            var newestTimestamp = entries.Count > 0 ? entries[^1].Timestamp : DateTime.MinValue;

            if (newestTimestamp != _lastLogTimestamp || entries.Count != Logs.Count)
            {
                var reversed = entries.Reverse().ToList();
                Logs.Clear();
                foreach (var entry in reversed)
                    Logs.Add(entry);
                _lastLogTimestamp = newestTimestamp;
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("Logging", $"Log refresh failed: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    // ═══════════════════════════════════════════════
    // Scanning — runs on background thread
    // Lifecycle: status text changes step-by-step
    // ═══════════════════════════════════════════════

    private async Task RunFullScanAsync()
    {
        if (!await _scanGate.WaitAsync(0)) return;
        IsScanning = true;
        ScanButtonText = "⟳ SCANNING...";

        try
        {
            // Step 1: Enumerate
            StatusText = "ENUMERATING PROCESSES...";
            var procs = await Task.Run(() => _scanner.ScanAll(_lifetime.Token), _lifetime.Token);

            // Step 2: Analyze
            StatusText = "ANALYZING BEHAVIOR...";
            await Task.Run(() => _scorer.ScoreAll(procs, _lifetime.Token), _lifetime.Token);
            var reports = await Task.Run(() => _scorer.GenerateReports(procs, ThreatLevel.Low, _lifetime.Token), _lifetime.Token);

            // Step 3: Network
            StatusText = "CORRELATING NETWORK ACTIVITY...";
            var processSnapshot = procs.ToDictionary(process => process.Pid);
            var conns = await Task.Run(() => _networkMonitor.GetConnections(processSnapshot, _lifetime.Token), _lifetime.Token);

            // Step 4: Update UI (incremental — avoids flicker)
            StatusText = "UPDATING RESULTS...";

            // Diff processes: update existing, add new, remove stale
            var procByPid = procs
                .GroupBy(p => p.Pid)
                .ToDictionary(group => group.Key, group => group.First());
            for (int i = Processes.Count - 1; i >= 0; i--)
            {
                if (!procByPid.ContainsKey(Processes[i].Pid))
                    Processes.RemoveAt(i);
            }
            for (int i = 0; i < Processes.Count; i++)
            {
                if (procByPid.TryGetValue(Processes[i].Pid, out var fresh))
                    Processes[i] = fresh;
            }
            var existingPids = new HashSet<int>(Processes.Select(p => p.Pid));
            foreach (var p in procByPid.Values)
                if (existingPids.Add(p.Pid)) Processes.Add(p);
            ProcessCount = procByPid.Count;

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

            var scanHealth = TelemetryHealth.Combine(_scanner.LastHealth, _networkMonitor.LastHealth, _systemMonitor.LastHealth);
            ApplyHealth(scanHealth);
            if (scanHealth.Level == TelemetryHealthLevel.Healthy)
                LastSuccessfulScanUtc = DateTime.UtcNow;

            // Final status
            StatusText = scanHealth.Level != TelemetryHealthLevel.Healthy
                ? $"⚠ MONITORING {scanHealth.Level.ToString().ToUpperInvariant()} — RESULTS MAY BE INCOMPLETE"
                : ThreatCount > 0
                ? $"⚠ {ThreatCount} THREATS DETECTED"
                : "NO SUSPICIOUS ACTIVITY DETECTED BY BLACKWATCH";
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.Error("Blackwatch", $"Scan failed: {ex.Message}");
            ApplyHealth(TelemetryHealth.Error($"Scan failed: {ex.Message}"));
            StatusText = "SCAN ERROR — PREVIOUS RESULTS MAY BE STALE";
        }
        finally
        {
            _scanGate.Release();
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

        if (!DryRunMode)
        {
            _logger.Warning("CleanerConsent", $"Live kill request for PID {pid} requires explicit confirmation.");
            StatusText = "CONFIRMATION REQUIRED FOR LIVE ACTION";
            return;
        }

        var result = _cleaner.KillProcess(pid, proc.Name, proc.StartTime, dryRun: DryRunMode);
        if (result.Success)
            _ = RunFullScanAsync();
    }

    private void ApplyHealth(TelemetryHealth health)
    {
        HealthLevel = health.Level;
        HealthMessage = health.Message;
    }

    private void ApplyOverallHealth() => ApplyHealth(TelemetryHealth.Combine(
        _scanner.LastHealth,
        _networkMonitor.LastHealth,
        _systemMonitor.LastHealth));

    public ProcessInfo? GetProcessForConfirmation(int pid) => Processes.FirstOrDefault(process => process.Pid == pid);
    public int PurgeTargetCount => Threats.Count(threat => threat.Score.Level >= ThreatLevel.High);

    public void ExecuteKillConfirmed(int pid)
    {
        var process = GetProcessForConfirmation(pid);
        if (process is null) return;
        var authorization = DryRunMode ? null : _cleaner.AuthorizeProcessKill(process.Pid, process.Name, process.StartTime);
        var result = _cleaner.KillProcess(process.Pid, process.Name, process.StartTime, dryRun: DryRunMode, authorization);
        StatusText = result.Success ? "RESPONSE ACTION COMPLETED" : "RESPONSE ACTION REJECTED";
        if (result.Success) _ = RunFullScanAsync();
    }

    private void OnNewProcessCreated(object? sender, ProcessCreatedEventArgs e)
    {
        _logger.Info("ProcessWatcher", $"New process: {e.ProcessName} (PID {e.Pid})");
        _ = RunFullScanAsync();
    }

    /// <summary>Executes a purge only after the native window has collected explicit consent.</summary>
    public void ExecutePurgeForced()
    {
        var criticals = Threats
            .Where(t => t.Score.Level >= ThreatLevel.High)
            .ToList();

        if (criticals.Count == 0) return;

        foreach (var threat in criticals)
        {
            var authorization = DryRunMode ? null : _cleaner.AuthorizeProcessKill(
                threat.Process.Pid,
                threat.Process.Name,
                threat.Process.StartTime);
            _cleaner.KillProcess(
                threat.Process.Pid,
                threat.Process.Name,
                threat.Process.StartTime,
                dryRun: DryRunMode,
                authorization);
        }

        _logger.Threat("Blackwatch", $"Purge executed: {criticals.Count} threats targeted");
        _ = RunFullScanAsync();
    }
    // ═══════════════════════════════════════════════
    // Whitelist Management
    // ═══════════════════════════════════════════════

    private void ExecuteRemoveWhitelist(string name)
    {
        if (string.IsNullOrEmpty(name)) return;
        WhitelistItems.Remove(name);
        _config.Whitelist = WhitelistItems.ToList();
        SaveConfig();
        OnPropertyChanged(nameof(WhitelistEmpty));
        _logger.Info("Settings", $"Removed from whitelist: {name}");
    }

    public void BrowseTrustedApplication()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select Executable to Whitelist",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*",
            Multiselect = false
        };

        if (dialog.ShowDialog() == true)
        {
            try
            {
                var identity = TrustedApplicationIdentity.Inspect(dialog.FileName);
                if (_config.TrustedApplications.Any(item =>
                        item.Sha256.Equals(identity.Sha256, StringComparison.OrdinalIgnoreCase) &&
                        item.CanonicalPath.Equals(identity.CanonicalPath, StringComparison.OrdinalIgnoreCase)))
                {
                    StatusText = "APPLICATION IS ALREADY TRUSTED";
                    return;
                }
                var publisher = string.IsNullOrWhiteSpace(identity.PublisherThumbprint)
                    ? "Unsigned"
                    : $"{identity.CompanyName} ({identity.PublisherThumbprint[..Math.Min(16, identity.PublisherThumbprint.Length)]}…)";
                var confirmation = System.Windows.MessageBox.Show(
                    $"Trust this exact executable identity?\n\n" +
                    $"Name: {identity.Name}\nPath: {identity.CanonicalPath}\n" +
                    $"SHA-256: {identity.Sha256}\nPublisher: {publisher}\n\n" +
                    "If the file changes, the exception will stop matching automatically.",
                    "Confirm Trusted Application",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning,
                    MessageBoxResult.No);
                if (confirmation != MessageBoxResult.Yes) return;

                _config.TrustedApplications.Add(identity);
                SaveConfig();
                OnPropertyChanged(nameof(TrustedApplications));
                _logger.Info("Settings", $"Added trusted executable identity: {identity.Name} ({identity.Sha256[..16]}…)");
                StatusText = "TRUSTED APPLICATION ADDED";
                _ = RunFullScanAsync();
            }
            catch (Exception ex)
            {
                _logger.Error("Settings", $"Could not inspect trusted executable: {ex.Message}");
                StatusText = "TRUSTED APPLICATION COULD NOT BE ADDED";
            }
        }
    }

    public void RemoveTrustedApplication(string trustId)
    {
        var item = _config.TrustedApplications.FirstOrDefault(rule =>
            rule.TrustId.Equals(trustId, StringComparison.Ordinal));
        if (item is null) return;
        _config.TrustedApplications.Remove(item);
        SaveConfig();
        OnPropertyChanged(nameof(TrustedApplications));
        _logger.Info("Settings", $"Removed trusted executable identity: {item.Name} ({item.Sha256[..Math.Min(16, item.Sha256.Length)]}…)");
        StatusText = "TRUSTED APPLICATION REMOVED";
        _ = RunFullScanAsync();
    }

    // ═══════════════════════════════════════════════
    // INotifyPropertyChanged
    // ═══════════════════════════════════════════════

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void LoggerWarning(string source, string message) => _logger.Warning(source, message);
    public void LoggerInfo(string source, string message) => _logger.Info(source, message);

    public void ExportDiagnosticBundle()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export Redacted Blackwatch Diagnostics",
            Filter = "ZIP archive (*.zip)|*.zip",
            FileName = $"Blackwatch-Diagnostics-{DateTime.Now:yyyyMMdd-HHmmss}.zip",
            AddExtension = true,
            DefaultExt = ".zip",
            OverwritePrompt = true
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            _logger.Flush();
            DiagnosticBundleExporter.Export(dialog.FileName, _logger.LogDirectory, new DiagnosticSummary(
                typeof(MainViewModel).Assembly
                    .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                    .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                    .FirstOrDefault()?.InformationalVersion ?? "0.1.0-alpha",
                HealthLevel.ToString(), HealthMessage, LastSuccessfulScanUtc, DryRunMode,
                ProcessCount, ThreatCount, ConnectionCount));
            _logger.Info("Diagnostics", "Exported a redacted diagnostic bundle to a user-selected location.");
            StatusText = "REDACTED DIAGNOSTIC BUNDLE EXPORTED";
        }
        catch (Exception ex)
        {
            _logger.Error("Diagnostics", $"Diagnostic export failed: {ex.Message}");
            StatusText = "DIAGNOSTIC EXPORT FAILED";
        }
    }

    private void SaveConfig()
    {
        if (!_config.Save())
        {
            var error = BlackwatchConfig.LastPersistenceError ?? "Unknown configuration error";
            _logger.Error("Config", error);
            StatusText = "SETTINGS COULD NOT BE SAVED";
        }
    }

    public CleanerAction? GetRecoveryForConfirmation(string actionId) =>
        RecoveryActions.FirstOrDefault(item => item.ActionId.Equals(actionId, StringComparison.Ordinal));

    public void ExecuteRecoveryActionConfirmed(string action, string actionId)
    {
        if (!Enum.TryParse<RecoveryActionKind>(action, ignoreCase: true, out var kind))
        {
            StatusText = "RECOVERY ACTION REJECTED";
            return;
        }
        var authorization = _cleaner.AuthorizeRecovery(actionId, kind);
        if (authorization is null)
        {
            StatusText = "RECOVERY ACTION IS STALE";
            return;
        }
        var success = kind switch
        {
            RecoveryActionKind.Restore => _cleaner.RestoreRecovery(actionId, authorization),
            RecoveryActionKind.Finalize => _cleaner.ResolveRecovery(actionId, completed: true, "User confirmed the interrupted mutation completed.", kind, authorization),
            RecoveryActionKind.Dismiss => _cleaner.ResolveRecovery(actionId, completed: false, "User confirmed the interrupted mutation did not complete or requires no further action.", kind, authorization),
            _ => false
        };
        StatusText = success ? "RECOVERY JOURNAL UPDATED" : "RECOVERY ACTION FAILED";
        OnPropertyChanged(nameof(RecoveryActions));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _lifetime.Cancel();
        _processWatcher.ProcessCreated -= OnNewProcessCreated;
        _processWatcher.Dispose();
        _systemMonitor.Dispose();
        _networkMonitor.Dispose();
        _logger.Dispose();
        _lifetime.Dispose();
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
