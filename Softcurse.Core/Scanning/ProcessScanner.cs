using System.Diagnostics;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Scanning;

/// <summary>
/// Enumerates running processes with full metadata:
/// path, command line, parent process, thread count, window visibility.
/// </summary>
public class ProcessScanner
{
    private readonly BlackwatchLogger _logger;
    private readonly int _processorCount;

    // CPU tracking: stores previous snapshot for delta calculation
    private readonly Dictionary<int, CpuSnapshot> _cpuSnapshots = new();

    // Enrichment cache is keyed by path and invalidated by file metadata.
    private readonly Dictionary<string, FileEnrichment> _hashCache = new(StringComparer.OrdinalIgnoreCase);
    private const int MaxEnrichmentCacheEntries = 4096;
    private string? _lastWmiError;
    public TelemetryHealth LastHealth { get; private set; } = TelemetryHealth.Error("Process telemetry has not completed yet.");

    private record CpuSnapshot(TimeSpan TotalCpu, DateTime MeasuredAt);
    private record FileEnrichment(long Length, DateTime LastWriteUtc, string Hash, bool? Signed, string PublisherThumbprint, string ProductName, string CompanyName);

    public ProcessScanner(BlackwatchLogger logger)
    {
        _logger = logger;
        _processorCount = Environment.ProcessorCount;
    }

    /// <summary>
    /// Full scan of all running processes with WMI enrichment.
    /// </summary>
    public List<ProcessInfo> ScanAll(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<ProcessInfo>();
        var wmiData = GetWmiProcessData(cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        var processes = Process.GetProcesses();

        foreach (var proc in processes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var info = new ProcessInfo
                {
                    Pid = proc.Id,
                    Name = proc.ProcessName,
                };

                // File path
                try { info.FilePath = proc.MainModule?.FileName ?? string.Empty; }
                catch { info.FilePath = string.Empty; }

                // SHA256 hash + Authenticode signature (cached)
                if (!string.IsNullOrEmpty(info.FilePath) && File.Exists(info.FilePath))
                {
                    try
                    {
                        var file = new FileInfo(info.FilePath);
                        if (_hashCache.TryGetValue(info.FilePath, out var cached) &&
                            cached.Length == file.Length &&
                            cached.LastWriteUtc == file.LastWriteTimeUtc)
                        {
                            info.FileHash = cached.Hash;
                            info.IsSigned = cached.Signed;
                            info.PublisherThumbprint = cached.PublisherThumbprint;
                            info.ProductName = cached.ProductName;
                            info.CompanyName = cached.CompanyName;
                        }
                        else
                        {
                            info.FileHash = ComputeSha256(info.FilePath);
                            var signature = VerifySignature(info.FilePath);
                            info.IsSigned = signature.IsSigned;
                            info.PublisherThumbprint = signature.PublisherThumbprint;
                            var version = FileVersionInfo.GetVersionInfo(info.FilePath);
                            info.ProductName = version.ProductName ?? string.Empty;
                            info.CompanyName = version.CompanyName ?? string.Empty;
                            if (_hashCache.Count >= MaxEnrichmentCacheEntries)
                                _hashCache.Clear();
                            _hashCache[info.FilePath] = new FileEnrichment(
                                file.Length,
                                file.LastWriteTimeUtc,
                                info.FileHash,
                                info.IsSigned,
                                info.PublisherThumbprint,
                                info.ProductName,
                                info.CompanyName);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Debug("ProcessScanner", $"Could not enrich {info.FilePath}: {ex.Message}");
                    }
                }

                // Memory
                try { info.MemoryMB = proc.WorkingSet64 / (1024.0 * 1024.0); }
                catch { }

                // CPU — delta calculation against previous snapshot
                try
                {
                    var now = DateTime.UtcNow;
                    var totalCpu = proc.TotalProcessorTime;
                    if (_cpuSnapshots.TryGetValue(proc.Id, out var prev))
                    {
                        var cpuDelta = (totalCpu - prev.TotalCpu).TotalMilliseconds;
                        var timeDelta = (now - prev.MeasuredAt).TotalMilliseconds;
                        if (timeDelta > 0)
                            info.CpuPercent = Math.Round(cpuDelta / (timeDelta * _processorCount) * 100, 1);
                    }
                    _cpuSnapshots[proc.Id] = new CpuSnapshot(totalCpu, now);
                }
                catch { }

                // Thread count
                try { info.ThreadCount = proc.Threads.Count; }
                catch { }

                // Has visible window
                try { info.HasWindow = proc.MainWindowHandle != IntPtr.Zero; }
                catch { }

                // Start time
                try { info.StartTime = proc.StartTime; }
                catch { info.StartTime = DateTime.MinValue; }

                // WMI enrichment: CommandLine + ParentPid
                if (wmiData.TryGetValue(proc.Id, out var wmi))
                {
                    info.CommandLine = wmi.CommandLine;
                    info.ParentPid = wmi.ParentPid;
                    info.ParentName = wmi.ParentName;
                    if (string.IsNullOrEmpty(info.FilePath) && !string.IsNullOrEmpty(wmi.ExecutablePath))
                        info.FilePath = wmi.ExecutablePath;
                }

                result.Add(info);
            }
            catch
            {
                // Process exited between enumeration and access.
            }
            finally
            {
                proc.Dispose();
            }
        }

        // Purge stale CPU snapshots for dead PIDs
        var activePids = new HashSet<int>(result.Select(r => r.Pid));
        foreach (var stale in _cpuSnapshots.Keys.Except(activePids).ToList())
            _cpuSnapshots.Remove(stale);

        _logger.Debug("ProcessScanner", $"Scanned {result.Count} processes");
        LastHealth = _lastWmiError is null
            ? TelemetryHealth.Healthy("Process telemetry is operational.")
            : TelemetryHealth.Degraded($"Process metadata is incomplete: {_lastWmiError}");
        return result.OrderByDescending(p => p.MemoryMB).ToList();
    }

    /// <summary>
    /// Grabs CommandLine, ParentProcessId, and ExecutablePath from WMI for all processes.
    /// </summary>
    private Dictionary<int, WmiProcessInfo> GetWmiProcessData(CancellationToken cancellationToken)
    {
        var dict = new Dictionary<int, WmiProcessInfo>();
        _lastWmiError = null;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine, ParentProcessId, ExecutablePath FROM Win32_Process");
            foreach (var obj in searcher.Get())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var pid = Convert.ToInt32(obj["ProcessId"]);
                var parentPid = Convert.ToInt32(obj["ParentProcessId"]);
                string parentName = string.Empty;
                try
                {
                    var parent = Process.GetProcessById(parentPid);
                    parentName = parent.ProcessName;
                    parent.Dispose();
                }
                catch { }

                dict[pid] = new WmiProcessInfo
                {
                    CommandLine = obj["CommandLine"]?.ToString() ?? string.Empty,
                    ParentPid = parentPid,
                    ParentName = parentName,
                    ExecutablePath = obj["ExecutablePath"]?.ToString() ?? string.Empty
                };
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _lastWmiError = ex.Message;
            _logger.Warning("ProcessScanner", $"WMI query failed: {ex.Message}");
        }
        return dict;
    }

    private record WmiProcessInfo
    {
        public string CommandLine { get; init; } = string.Empty;
        public int ParentPid { get; init; }
        public string ParentName { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
    }

    // ── SHA256 Hash ──
    private static string ComputeSha256(string filePath)
    {
        using var stream = File.OpenRead(filePath);
        var hash = SHA256.HashData(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ── Authenticode Signature Check ──
    private static SignatureInfo VerifySignature(string filePath)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = X509Certificate2.CreateFromSignedFile(filePath);
#pragma warning restore SYSLIB0057
            using var cert = new X509Certificate2(certificate);
            return new SignatureInfo(true, cert.Thumbprint ?? string.Empty);
        }
        catch (CryptographicException)
        {
            return new SignatureInfo(false, string.Empty);
        }
        catch (UnauthorizedAccessException)
        {
            return new SignatureInfo(null, string.Empty);
        }
        catch (IOException)
        {
            return new SignatureInfo(null, string.Empty);
        }
    }

    private readonly record struct SignatureInfo(bool? IsSigned, string PublisherThumbprint);
}
