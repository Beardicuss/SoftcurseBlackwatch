using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Softcurse.Shared.Security;
using Softcurse.UI.ViewModels;

namespace Softcurse.UI;

public partial class MainWindow : Window
{
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private MainViewModel? _vm;
    private readonly CancellationTokenSource _dataPushLifetime = new();
    private Task? _dataPushTask;
    private readonly Dictionary<string, string> _lastWebPayloads = new(StringComparer.Ordinal);
    private readonly CommandRateLimiter _bridgeRateLimiter = new();

    public MainWindow()
    {
        InitializeComponent();

        _vm = new MainViewModel();
        DataContext = _vm;

        Loaded += MainWindow_Loaded;
        InitializeTrayIcon();
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            var webUiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WebUI");
            await using var integrityManifest = typeof(MainWindow).Assembly.GetManifestResourceStream("Softcurse.UI.WebUI.sha256")
                ?? throw new InvalidDataException("The embedded WebUI integrity manifest is missing.");
            var integrity = WebUiIntegrityVerifier.Verify(webUiPath, integrityManifest);
            if (!integrity.Success)
            {
                _vm?.LoggerWarning("WebUIIntegrity", integrity.Message);
                System.Windows.MessageBox.Show(
                    $"Blackwatch blocked the interface because its installed files failed integrity verification.\n\n{integrity.Message}\n\nReinstall Blackwatch from an authentic release.",
                    "Blackwatch Integrity Failure",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return;
            }
            _vm?.LoggerInfo("WebUIIntegrity", integrity.Message);

            var env = await CoreWebView2Environment.CreateAsync(
                userDataFolder: Path.Combine(Path.GetTempPath(), "SoftcurseBlackwatch_WV2"));
            await MainWebView.EnsureCoreWebView2Async(env);

            MainWebView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 6, 11, 24);

            // Disable context menus, devtools, zoom
            MainWebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            MainWebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            MainWebView.CoreWebView2.Settings.IsZoomControlEnabled = false;
            MainWebView.CoreWebView2.Settings.IsStatusBarEnabled = false;
            MainWebView.CoreWebView2.Settings.IsWebMessageEnabled = true;

            // Map the WebUI folder to a virtual hostname
            MainWebView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "blackwatch.local", webUiPath,
                CoreWebView2HostResourceAccessKind.DenyCors);

            MainWebView.CoreWebView2.NavigationStarting += (_, args) =>
            {
                if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var target) ||
                    target.Scheme != Uri.UriSchemeHttps ||
                    !target.Host.Equals("blackwatch.local", StringComparison.OrdinalIgnoreCase))
                {
                    args.Cancel = true;
                    _vm?.LoggerWarning("WebView", $"Blocked navigation to {args.Uri}");
                }
            };
            MainWebView.CoreWebView2.NewWindowRequested += (_, args) =>
            {
                args.Handled = true;
                _vm?.LoggerWarning("WebView", $"Blocked new window request to {args.Uri}");
            };
            MainWebView.CoreWebView2.NavigationCompleted += (_, args) =>
            {
                if (!args.IsSuccess) return;
                _lastWebPayloads.Clear();
                Dispatcher.BeginInvoke(PushDataToWebView, System.Windows.Threading.DispatcherPriority.ContextIdle);
            };

            // Navigate to the React app
            MainWebView.CoreWebView2.Navigate("https://blackwatch.local/index.html");

            // Listen for messages from JS (commands like scan, purge, navigate)
            MainWebView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;

            _dataPushTask = RunDataPushLoopAsync(_dataPushLifetime.Token);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"WebView2 initialization failed:\n{ex.Message}",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ═══════════════════════════════════════════════
    // C# → JS Data Push (dashboard + active view data)
    // ═══════════════════════════════════════════════

    private async Task RunDataPushLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            PushDataToWebView();
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
                await Dispatcher.InvokeAsync(PushDataToWebView, System.Windows.Threading.DispatcherPriority.Background, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _vm?.LoggerWarning("WebView", $"Data channel stopped unexpectedly: {ex.Message}");
        }
    }

    private void PushDataToWebView()
    {
        if (_vm == null || MainWebView?.CoreWebView2 == null) return;

        try
        {
            // Snapshot the history arrays safely
            float[] cpuHistory;
            float[] ramHistory;
            lock (_vm.CpuHistory) { cpuHistory = _vm.CpuHistory.ToArray(); }
            lock (_vm.RamHistory) { ramHistory = _vm.RamHistory.ToArray(); }

            // Always push dashboard data
            var dashData = new
            {
                cpu = _vm.CpuUsage,
                ramUsedMB = _vm.RamUsedMB,
                ramPercent = _vm.RamUsage,
                processCount = _vm.ProcessCount,
                threatCount = _vm.ThreatCount,
                cpuHistory,
                ramHistory,
                statusText = _vm.StatusText ?? "NO SUSPICIOUS ACTIVITY DETECTED",
                isScanning = _vm.IsScanning,
                healthLevel = _vm.HealthLevel.ToString(),
                healthMessage = _vm.HealthMessage,
                lastSuccessfulScanUtc = _vm.LastSuccessfulScanUtc
            };
            PostSnapshot("dashboard", dashData);

            // Push active-view-specific data
            var view = _vm.ActiveView;
            PostSnapshot("activeView", view);

            switch (view)
            {
                case 1: // Threats
                    var threatSnap = _vm.Threats.ToList();
                    var threats = threatSnap.Select(t => new
                    {
                        level = t.Score.Level.ToString(),
                        score = t.Score.Total,
                        processName = t.Process.Name ?? "",
                        pid = t.Process.Pid,
                        path = t.Process.FilePath ?? "",
                        action = t.RecommendedAction ?? "",
                        confidence = t.Score.Confidence.ToString(),
                        explanation = t.Score.Explanation ?? "",
                        ruleSetVersion = t.Score.RuleSetVersion ?? "",
                        evidence = t.Score.Signals.Select(signal => new
                        {
                            evidenceId = signal.EvidenceId ?? "",
                            name = signal.Name ?? "",
                            description = signal.Description ?? "",
                            observedValue = signal.ObservedValue ?? "",
                            weight = signal.Weight,
                            category = signal.Category.ToString(),
                            confidence = signal.Confidence.ToString(),
                            ruleVersion = signal.RuleVersion ?? ""
                        }).ToList()
                    }).ToList();
                    var threatPayload = new { items = threats, count = _vm.ThreatCount };
                    PostSnapshot("threats", threatPayload);
                    break;

                case 2: // Processes
                    var procSnap = _vm.Processes.ToList();
                    var procs = procSnap.Select(p => new
                    {
                        name = p.Name ?? "",
                        pid = p.Pid,
                        memoryMB = p.MemoryMB,
                        threadCount = p.ThreadCount,
                        parentName = p.ParentName ?? "",
                        path = p.FilePath ?? "",
                        productName = p.ProductName ?? "",
                        companyName = p.CompanyName ?? "",
                        signed = p.IsSigned,
                        level = p.Score.Level.ToString()
                    }).ToList();
                    var procPayload = new { items = procs, count = _vm.ProcessCount };
                    PostSnapshot("processes", procPayload);
                    break;

                case 3: // Network
                    var connSnap = _vm.Connections.ToList();
                    var conns = connSnap.Select(c => new
                    {
                        state = c.State ?? "",
                        connectionId = c.ConnectionId ?? "",
                        protocol = c.Protocol ?? "",
                        addressFamily = c.AddressFamily ?? "",
                        processName = c.ProcessName ?? "",
                        processIsSigned = c.ProcessIsSigned,
                        processCompanyName = c.ProcessCompanyName ?? "",
                        processFileHash = c.ProcessFileHash ?? "",
                        localEndpoint = c.LocalEndpoint ?? "",
                        remoteEndpoint = c.RemoteEndpoint ?? "",
                        remoteHostName = c.RemoteHostName ?? "",
                        remotePort = c.RemotePort,
                        suspiciousReason = c.SuspiciousReason ?? "",
                        confidence = c.Confidence.ToString(),
                        firstSeenUtc = c.FirstSeenUtc,
                        lastSeenUtc = c.LastSeenUtc,
                        observationCount = c.ObservationCount,
                        evidence = c.Evidence.Select(item => new
                        {
                            ruleId = item.RuleId ?? "",
                            description = item.Description ?? "",
                            observedValue = item.ObservedValue ?? "",
                            confidence = item.Confidence.ToString(),
                            sourceEvidenceId = item.SourceEvidenceId ?? ""
                        }).ToList()
                    }).ToList();
                    var netPayload = new { items = conns, count = _vm.ConnectionCount, suspiciousCount = _vm.SuspiciousConnectionCount };
                    PostSnapshot("network", netPayload);
                    break;

                case 4: // Logs
                    var logSnap = _vm.Logs.ToList();
                    var logs = logSnap.Select(l => new
                    {
                        timestamp = l.Timestamp.ToString("HH:mm:ss.fff"),
                        level = l.Level.ToString(),
                        source = l.Source ?? "",
                        message = l.Message ?? ""
                    }).ToList();
                    var logPayload = new { items = logs };
                    PostSnapshot("logs", logPayload);
                    break;

                case 5: // Settings
                    var settingsPayload = new
                    {
                        dryRunMode = _vm.DryRunMode,
                        minimizeToTray = _vm.MinimizeToTray,
                        whitelistItems = _vm.WhitelistItems.ToList(),
                        trustedApplications = _vm.TrustedApplications.Select(item => new
                        {
                            trustId = item.TrustId,
                            name = item.Name,
                            canonicalPath = item.CanonicalPath,
                            sha256 = item.Sha256,
                            publisherThumbprint = item.PublisherThumbprint,
                            productName = item.ProductName,
                            companyName = item.CompanyName,
                            reason = item.Reason,
                            createdUtc = item.CreatedUtc,
                            expiresUtc = item.ExpiresUtc
                        }).ToList(),
                        cpuSpikeThreshold = _vm.CpuSpikeThreshold,
                        cpuSpikeDuration = _vm.CpuSpikeDuration,
                        recoveryActions = _vm.RecoveryActions.Select(action => new
                        {
                            actionId = action.ActionId,
                            actionType = action.ActionType.ToString(),
                            targetName = action.TargetName ?? "",
                            targetPath = action.TargetPath ?? "",
                            quarantinePath = action.QuarantinePath ?? "",
                            status = action.Status.ToString(),
                            errorMessage = action.ErrorMessage ?? ""
                        }).ToList()
                    };
                    PostSnapshot("settings", settingsPayload);
                    break;
            }
        }
        catch (Exception ex) when (_dataPushLifetime.IsCancellationRequested || MainWebView?.CoreWebView2 is null)
        {
            System.Diagnostics.Debug.WriteLine($"WebView data push stopped: {ex.Message}");
        }
    }

    private void PostSnapshot(string channel, object data)
    {
        var payload = JsonSerializer.Serialize(new { version = 1, type = "snapshot", channel, data });
        if (_lastWebPayloads.TryGetValue(channel, out var previous) && previous == payload) return;
        MainWebView.CoreWebView2.PostWebMessageAsJson(payload);
        _lastWebPayloads[channel] = payload;
    }

    // ═══════════════════════════════════════════════
    // JS → C# Command Handling
    // ═══════════════════════════════════════════════

    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            if (!Uri.TryCreate(e.Source, UriKind.Absolute, out var source) ||
                source.Scheme != Uri.UriSchemeHttps ||
                !source.Host.Equals("blackwatch.local", StringComparison.OrdinalIgnoreCase))
            {
                _vm?.LoggerWarning("Bridge", $"Rejected message from untrusted origin: {e.Source}");
                return;
            }

            var command = JsonSerializer.Deserialize<BridgeCommand>(
                e.WebMessageAsJson,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (command is null || command.Version != 1)
            {
                _vm?.LoggerWarning("Bridge", "Rejected malformed or unsupported bridge message");
                return;
            }
            if (RateLimitFor(command) is { } limit &&
                !_bridgeRateLimiter.TryAcquire(limit.Key, limit.Cooldown))
            {
                _vm?.LoggerWarning("Bridge", $"Rate-limited command: {command.Type}/{command.Action}");
                return;
            }

            switch (command.Type)
            {
                case "window" when command.Action == "minimize":
                    WindowState = WindowState.Minimized;
                    break;
                case "window" when command.Action == "maximize":
                    WindowState = WindowState == WindowState.Maximized
                        ? WindowState.Normal
                        : WindowState.Maximized;
                    break;
                case "window" when command.Action == "close":
                    Close();
                    break;
                case "window" when command.Action == "dragstart":
                    try {
                        if (WindowState == WindowState.Maximized)
                            WindowState = WindowState.Normal;
                        DragMove();
                    } catch { /* mouse button not held */ }
                    break;
                case "app" when command.Action == "scan":
                    _vm?.ScanNowCommand.Execute(null);
                    break;
                case "app" when command.Action == "purge":
                    _ = ShowPurgeConfirm();
                    break;
                case "navigate" when command.ViewId is >= 0 and <= 6:
                    if (_vm != null) _vm.ActiveView = command.ViewId.Value;
                    break;
                case "process" when command.Action == "kill" && command.Pid > 0:
                    ShowKillConfirm(command.Pid.Value);
                    break;
                case "setting" when command.Action == "dryrun" && command.Enabled is bool dryRun:
                    ShowDryRunChange(dryRun);
                    break;
                case "setting" when command.Action == "tray" && command.Enabled is bool tray:
                    if (_vm != null) _vm.MinimizeToTray = tray;
                    break;
                case "whitelist" when command.Action == "remove" && !string.IsNullOrWhiteSpace(command.Value):
                    _vm?.RemoveWhitelistCommand.Execute(command.Value);
                    break;
                case "trusted" when command.Action == "browse":
                    _vm?.BrowseTrustedApplication();
                    break;
                case "trusted" when command.Action == "remove" && !string.IsNullOrWhiteSpace(command.Value):
                    _vm?.RemoveTrustedApplication(command.Value);
                    break;
                case "recovery" when command.Action is "restore" or "finalize" or "dismiss" && !string.IsNullOrWhiteSpace(command.Value):
                    ShowRecoveryConfirm(command.Action, command.Value);
                    break;
                case "diagnostics" when command.Action == "export":
                    _vm?.ExportDiagnosticBundle();
                    break;
                default:
                    _vm?.LoggerWarning("Bridge", $"Rejected unsupported command: {command.Type}/{command.Action}");
                    break;
            }
        }
        catch (Exception ex)
        {
            _vm?.LoggerWarning("Bridge", $"Invalid bridge message: {ex.Message}");
        }
    }

    // ═══════════════════════════════════════════════
    // Native consent gates. Web content may request an action, but cannot confirm it.
    // ═══════════════════════════════════════════════

    private void ShowKillConfirm(int pid)
    {
        if (_vm == null) return;
        var process = _vm.GetProcessForConfirmation(pid);
        if (process == null)
        {
            _vm.LoggerWarning("CleanerConsent", $"Rejected kill confirmation for stale PID {pid}.");
            return;
        }

        if (_vm.DryRunMode)
        {
            _vm.ExecuteKillConfirmed(pid);
            return;
        }

        var signature = process.IsSigned switch
        {
            true => "Signed",
            false => "Unsigned",
            _ => "Unknown"
        };
        var hash = string.IsNullOrWhiteSpace(process.FileHash)
            ? "Unavailable"
            : process.FileHash[..Math.Min(16, process.FileHash.Length)] + "…";
        var message =
            "Terminate this process and its child-process tree?\n\n" +
            $"Name: {process.Name}\n" +
            $"PID: {process.Pid}\n" +
            $"Started: {process.StartTime:O}\n" +
            $"Executable: {(string.IsNullOrWhiteSpace(process.FilePath) ? "Unavailable" : process.FilePath)}\n" +
            $"Signature: {signature}\n" +
            $"Company: {(string.IsNullOrWhiteSpace(process.CompanyName) ? "Unavailable" : process.CompanyName)}\n" +
            $"SHA-256: {hash}\n\n" +
            "This is a live system mutation and may cause data loss.";

        if (System.Windows.MessageBox.Show(
                this,
                message,
                "Confirm Blackwatch Response Action",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) == MessageBoxResult.Yes)
            _vm.ExecuteKillConfirmed(pid);
    }

    private Task ShowPurgeConfirm()
    {
        if (_vm == null) return Task.CompletedTask;
        var count = _vm.PurgeTargetCount;
        if (count == 0)
        {
            System.Windows.MessageBox.Show(this, "No high-confidence threats are available to purge.",
                "Softcurse Blackwatch", MessageBoxButton.OK, MessageBoxImage.Information);
            return Task.CompletedTask;
        }

        var mode = _vm.DryRunMode
            ? "DRY-RUN: no processes will be changed."
            : "LIVE: every high-confidence target and its child-process tree will be terminated.";
        var result = System.Windows.MessageBox.Show(
            this,
            $"Run the Blackwatch purge against {count} detected threat(s)?\n\n{mode}\n\n" +
            "Each target will be identity-checked immediately before the action.",
            "Confirm Blackwatch Purge",
            MessageBoxButton.YesNo,
            _vm.DryRunMode ? MessageBoxImage.Question : MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (result == MessageBoxResult.Yes)
            _vm.ExecutePurgeForced();
        return Task.CompletedTask;
    }

    private void ShowRecoveryConfirm(string operation, string actionId)
    {
        if (_vm == null) return;
        var recovery = _vm.GetRecoveryForConfirmation(actionId);
        if (recovery == null)
        {
            _vm.LoggerWarning("CleanerConsent", $"Rejected recovery confirmation for stale action {actionId}.");
            return;
        }

        var effect = operation switch
        {
            "restore" => "Verify the quarantined file and move it back to its original path. Existing files will never be overwritten.",
            "finalize" => "Record that the interrupted operation completed. This changes the durable recovery journal.",
            "dismiss" => "Record that the interrupted operation did not complete or needs no further action. This changes the durable recovery journal.",
            _ => string.Empty
        };
        if (effect.Length == 0) return;

        var message =
            $"Recovery operation: {operation.ToUpperInvariant()}\n\n" +
            $"Action ID: {recovery.ActionId}\n" +
            $"Action type: {recovery.ActionType}\n" +
            $"Target: {(string.IsNullOrWhiteSpace(recovery.TargetPath) ? recovery.TargetName : recovery.TargetPath)}\n" +
            $"Quarantine: {(string.IsNullOrWhiteSpace(recovery.QuarantinePath) ? "Not applicable" : recovery.QuarantinePath)}\n\n" +
            effect;

        if (System.Windows.MessageBox.Show(
                this,
                message,
                "Confirm Blackwatch Recovery Action",
                MessageBoxButton.YesNo,
                operation == "restore" ? MessageBoxImage.Warning : MessageBoxImage.Question,
                MessageBoxResult.No) == MessageBoxResult.Yes)
            _vm.ExecuteRecoveryActionConfirmed(operation, actionId);
    }

    private void ShowDryRunChange(bool enabled)
    {
        if (_vm == null) return;
        if (enabled)
        {
            _vm.DryRunMode = true;
            _vm.StatusText = "DRY-RUN SAFETY ENABLED";
            return;
        }
        if (!_vm.DryRunMode) return;

        var result = System.Windows.MessageBox.Show(
            this,
            "Disable dry-run safety?\n\nBlackwatch will be allowed to terminate explicitly confirmed process targets and perform explicitly confirmed recovery operations. Automatic response remains disabled.",
            "Enable Live Response Mode",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (result == MessageBoxResult.Yes)
        {
            _vm.DryRunMode = false;
            _vm.StatusText = "LIVE RESPONSE MODE ENABLED";
        }
        else
        {
            _vm.DryRunMode = true;
            _vm.StatusText = "DRY-RUN SAFETY REMAINS ENABLED";
        }
    }

    private static BridgeRateLimit? RateLimitFor(BridgeCommand command) => (command.Type, command.Action) switch
    {
        ("app", "scan") => new("scan", TimeSpan.FromSeconds(2)),
        ("app", "purge") => new("purge-prompt", TimeSpan.FromSeconds(15)),
        ("process", "kill") when command.Pid > 0 =>
            new($"kill-prompt:{command.Pid}", TimeSpan.FromSeconds(10)),
        ("recovery", "restore" or "finalize" or "dismiss") when !string.IsNullOrWhiteSpace(command.Value) =>
            new($"recovery-prompt:{command.Action}:{command.Value}", TimeSpan.FromSeconds(30)),
        ("trusted", "browse") => new("trusted-picker", TimeSpan.FromSeconds(10)),
        ("diagnostics", "export") => new("diagnostic-export", TimeSpan.FromSeconds(30)),
        ("setting", "dryrun") => new("dryrun-change", TimeSpan.FromSeconds(3)),
        _ => null
    };

    // ═══════════════════════════════════════════════
    // System Tray (preserved from original)
    // ═══════════════════════════════════════════════

    private void InitializeTrayIcon()
    {
        var iconPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
        var icon = File.Exists(iconPath)
            ? new System.Drawing.Icon(iconPath)
            : System.Drawing.SystemIcons.Shield;

        _trayIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = icon,
            Text = "Softcurse Blackwatch",
            Visible = false
        };

        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Show Blackwatch", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Scan Now", null, (_, _) =>
        {
            RestoreFromTray();
            _vm?.ScanNowCommand.Execute(null);
        });
        menu.Items.Add("-");
        menu.Items.Add("Exit", null, (_, _) => ForceExit());
        _trayIcon.ContextMenuStrip = menu;
        _trayIcon.DoubleClick += (_, _) => RestoreFromTray();
    }

    private void MinimizeToTray()
    {
        Hide();
        if (_trayIcon != null)
        {
            _trayIcon.Visible = true;
            _trayIcon.ShowBalloonTip(2000, "Softcurse Blackwatch",
                "Running in background. Double-click to restore.",
                System.Windows.Forms.ToolTipIcon.Info);
        }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
        if (_trayIcon != null) _trayIcon.Visible = false;
    }

    private void ForceExit()
    {
        _dataPushLifetime.Cancel();
        if (_trayIcon != null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }
        _vm?.Dispose();
        MainWebView?.Dispose();
        System.Windows.Application.Current.Shutdown();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_vm is { MinimizeToTray: true })
        {
            e.Cancel = true;
            MinimizeToTray();
            return;
        }
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _dataPushLifetime.Cancel();
        if (_trayIcon != null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        _vm?.Dispose();
        MainWebView?.Dispose();
        _dataPushLifetime.Dispose();
        base.OnClosed(e);
    }
}

internal sealed class BridgeCommand
{
    public int Version { get; init; }
    public string Type { get; init; } = string.Empty;
    public string? Action { get; init; }
    public int? ViewId { get; init; }
    public int? Pid { get; init; }
    public bool? Enabled { get; init; }
    public string? Value { get; init; }
}

internal sealed record BridgeRateLimit(string Key, TimeSpan Cooldown);
