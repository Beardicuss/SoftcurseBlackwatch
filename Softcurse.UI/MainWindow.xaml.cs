using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Softcurse.UI.ViewModels;

namespace Softcurse.UI;

public partial class MainWindow : Window
{
    private System.Windows.Forms.NotifyIcon? _trayIcon;
    private MainViewModel? _vm;
    private DispatcherTimer? _dataPushTimer;

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
            var env = await CoreWebView2Environment.CreateAsync(
                userDataFolder: Path.Combine(Path.GetTempPath(), "SoftcurseSentinel_WV2"));
            await MainWebView.EnsureCoreWebView2Async(env);

            MainWebView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 6, 11, 24);

            // Disable context menus, devtools, zoom
            MainWebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            MainWebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
            MainWebView.CoreWebView2.Settings.IsZoomControlEnabled = false;
            MainWebView.CoreWebView2.Settings.IsStatusBarEnabled = false;

            // Map the WebUI folder to a virtual hostname
            var webUiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "WebUI");
            MainWebView.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "sentinel.local", webUiPath,
                CoreWebView2HostResourceAccessKind.Allow);

            // Navigate to the React app
            MainWebView.CoreWebView2.Navigate("https://sentinel.local/index.html");

            // Listen for messages from JS (commands like scan, purge, navigate)
            MainWebView.CoreWebView2.WebMessageReceived += OnWebMessageReceived;

            // Start pushing data to JS every ~1 second
            _dataPushTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(1000)
            };
            _dataPushTimer.Tick += PushDataToJs;
            _dataPushTimer.Start();
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

    private async void PushDataToJs(object? sender, EventArgs e)
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
                statusText = _vm.StatusText ?? "SYSTEM SECURE",
                isScanning = _vm.IsScanning
            };
            await ExecJs($"if(window.updateSentinelData) window.updateSentinelData('{Esc(dashData)}')");

            // Push active-view-specific data
            var view = _vm.ActiveView;
            await ExecJs($"if(window.setActiveView) window.setActiveView({view})");

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
                        action = t.RecommendedAction ?? ""
                    }).ToList();
                    var threatPayload = new { items = threats, count = _vm.ThreatCount };
                    await ExecJs($"if(window.updateThreats) window.updateThreats('{Esc(threatPayload)}')");
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
                        level = p.Score.Level.ToString()
                    }).ToList();
                    var procPayload = new { items = procs, count = _vm.ProcessCount };
                    await ExecJs($"if(window.updateProcesses) window.updateProcesses('{Esc(procPayload)}')");
                    break;

                case 3: // Network
                    var connSnap = _vm.Connections.ToList();
                    var conns = connSnap.Select(c => new
                    {
                        state = c.State ?? "",
                        processName = c.ProcessName ?? "",
                        localEndpoint = c.LocalEndpoint ?? "",
                        remoteEndpoint = c.RemoteEndpoint ?? "",
                        remotePort = c.RemotePort,
                        suspiciousReason = c.SuspiciousReason ?? ""
                    }).ToList();
                    var netPayload = new { items = conns, count = _vm.ConnectionCount, suspiciousCount = _vm.SuspiciousConnectionCount };
                    await ExecJs($"if(window.updateNetwork) window.updateNetwork('{Esc(netPayload)}')");
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
                    await ExecJs($"if(window.updateLogs) window.updateLogs('{Esc(logPayload)}')");
                    break;

                case 5: // Settings
                    var settingsPayload = new
                    {
                        dryRunMode = _vm.DryRunMode,
                        minimizeToTray = _vm.MinimizeToTray,
                        whitelistItems = _vm.WhitelistItems.ToList(),
                        cpuSpikeThreshold = _vm.CpuSpikeThreshold,
                        cpuSpikeDuration = _vm.CpuSpikeDuration
                    };
                    await ExecJs($"if(window.updateSettings) window.updateSettings('{Esc(settingsPayload)}')");
                    break;
            }
        }
        catch { /* WebView2 might be disposed during shutdown */ }
    }

    private string Esc(object data)
    {
        var json = JsonSerializer.Serialize(data);
        return json.Replace("\\", "\\\\").Replace("'", "\\'")
                   .Replace("\n", "\\n").Replace("\r", "\\r")
                   .Replace("\t", "\\t");
    }

    private async Task ExecJs(string script)
    {
        if (MainWebView?.CoreWebView2 != null)
            await MainWebView.CoreWebView2.ExecuteScriptAsync(script);
    }

    // ═══════════════════════════════════════════════
    // JS → C# Command Handling
    // ═══════════════════════════════════════════════

    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            var msg = e.TryGetWebMessageAsString();
            if (msg == null) return;

            // Protocol: "command" or "command:arg" or "command:sub:value"
            var parts = msg.Split(':', 3);
            var cmd = parts[0];
            var arg = parts.Length > 1 ? parts[1] : "";
            var val = parts.Length > 2 ? parts[2] : "";

            switch (cmd)
            {
                // Window controls
                case "minimize":
                    WindowState = WindowState.Minimized;
                    break;
                case "maximize":
                    WindowState = WindowState == WindowState.Maximized
                        ? WindowState.Normal
                        : WindowState.Maximized;
                    break;
                case "close":
                    Close();
                    break;
                case "dragstart":
                    try {
                        if (WindowState == WindowState.Maximized)
                            WindowState = WindowState.Normal;
                        DragMove();
                    } catch { /* mouse button not held */ }
                    break;

                // App commands
                case "scan":
                    _vm?.ScanNowCommand.Execute(null);
                    break;
                case "purge":
                    // Show JS confirm dialog instead of native MessageBox
                    _ = ShowPurgeConfirm();
                    break;
                case "purge_confirmed":
                    _vm?.ExecutePurgeForced();
                    break;
                case "navigate":
                    if (int.TryParse(arg, out int viewId) && _vm != null)
                        _vm.ActiveView = viewId;
                    break;
                case "kill":
                    if (int.TryParse(arg, out int pid))
                        _vm?.KillProcessCommand.Execute(pid);
                    break;

                // Settings
                case "setting":
                    if (_vm != null)
                    {
                        switch (arg)
                        {
                            case "dryrun":
                                _vm.DryRunMode = val.Equals("true", StringComparison.OrdinalIgnoreCase);
                                break;
                            case "tray":
                                _vm.MinimizeToTray = val.Equals("true", StringComparison.OrdinalIgnoreCase);
                                break;
                        }
                    }
                    break;

                // Whitelist
                case "whitelist":
                    if (_vm != null)
                    {
                        switch (arg)
                        {
                            case "add":
                                _vm.WhitelistInput = val;
                                _vm.AddWhitelistCommand.Execute(null);
                                break;
                            case "remove":
                                _vm.RemoveWhitelistCommand.Execute(val);
                                break;
                            case "browse":
                                _vm.BrowseWhitelistCommand.Execute(null);
                                break;
                        }
                    }
                    break;
            }
        }
        catch { /* ignore bad messages */ }
    }

    // ═══════════════════════════════════════════════
    // Purge Confirm via JS (replaces native MessageBox)
    // ═══════════════════════════════════════════════

    private async Task ShowPurgeConfirm()
    {
        if (_vm == null || MainWebView?.CoreWebView2 == null) return;
        var count = _vm.ThreatCount;
        if (count == 0)
        {
            await ExecJs("alert('No threats to purge')");
            return;
        }
        var mode = _vm.DryRunMode ? "DRY-RUN (no real action)" : "LIVE — PROCESSES WILL BE TERMINATED";
        var msg = $"PURGE {count} threats?\\n\\nMode: {mode}";
        await ExecJs($"if(confirm('{msg}')) window.chrome.webview.postMessage('purge_confirmed')");
    }

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
            Text = "Softcurse Sentinel",
            Visible = false
        };

        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Show Sentinel", null, (_, _) => RestoreFromTray());
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
            _trayIcon.ShowBalloonTip(2000, "Softcurse Sentinel",
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
        _dataPushTimer?.Stop();
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
        _dataPushTimer?.Stop();
        if (_trayIcon != null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        _vm?.Dispose();
        MainWebView?.Dispose();
        base.OnClosed(e);
    }
}