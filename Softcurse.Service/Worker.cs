using Softcurse.Core.Detection;
using Softcurse.Core.Scanning;
using Softcurse.Monitor;
using Softcurse.Shared.Config;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Service;

/// <summary>
/// Background service that runs the Softcurse Blackwatch monitoring loop.
/// Scans processes, scores threats, and logs findings.
/// </summary>
public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _msLogger;
    private readonly BlackwatchLogger _logger;
    private readonly BlackwatchConfig _config;
    private readonly ProcessScanner _scanner;
    private readonly ThreatScorer _scorer;
    private readonly ProcessWatcher _processWatcher;
    private readonly NetworkMonitor _networkMonitor;

    public Worker(ILogger<Worker> msLogger)
    {
        _msLogger = msLogger;
        _config = BlackwatchConfig.Load();
        _logger = new BlackwatchLogger();
        _scanner = new ProcessScanner(_logger);
        _scorer = new ThreatScorer(_logger, _config);
        _processWatcher = new ProcessWatcher(_logger);
        _networkMonitor = new NetworkMonitor(_logger);
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.Info("Service", "Softcurse Blackwatch Service starting...");
        _processWatcher.ProcessCreated += OnNewProcess;
        _processWatcher.Start();
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.Info("Service", "Monitoring loop started");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Scan all processes
                var procs = _scanner.ScanAll();
                _scorer.ScoreAll(procs);

                // Generate reports for anything suspicious+
                var reports = _scorer.GenerateReports(procs, ThreatLevel.Suspicious);

                foreach (var report in reports)
                {
                    _logger.Threat("Service",
                        $"[{report.Score.Level}] {report.Process.Name} (PID {report.Process.Pid}) " +
                        $"Score={report.Score.Total} Action={report.RecommendedAction}");
                }

                // Check network
                var processSnapshot = procs.ToDictionary(process => process.Pid);
                var connections = _networkMonitor.GetConnections(processSnapshot);
                var suspicious = connections.Where(c => c.IsSuspicious).ToList();
                if (suspicious.Count > 0)
                {
                    foreach (var conn in suspicious)
                    {
                        _logger.Threat("Service",
                            $"Suspicious network: {conn.RemoteEndpoint} — {conn.SuspiciousReason}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.Error("Service", $"Scan cycle failed: {ex.Message}");
            }

            try
            {
                await Task.Delay(_config.ScanIntervalMs, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        _logger.Info("Service", "Monitoring loop stopped");
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.Info("Service", "Softcurse Blackwatch Service stopping...");
        await base.StopAsync(cancellationToken);
        _processWatcher.ProcessCreated -= OnNewProcess;
        _processWatcher.Dispose();
        _networkMonitor.Dispose();
        _logger.Dispose();
    }

    private void OnNewProcess(object? sender, ProcessCreatedEventArgs e)
    {
        _logger.Info("Service", $"New process detected: {e.ProcessName} (PID {e.Pid})");
    }
}
