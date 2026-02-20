using System.Diagnostics;
using System.Management;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Core.Scanning;

/// <summary>
/// Enumerates running processes with full metadata:
/// path, command line, parent process, thread count, window visibility.
/// </summary>
public class ProcessScanner
{
    private readonly SentinelLogger _logger;

    public ProcessScanner(SentinelLogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Full scan of all running processes with WMI enrichment.
    /// </summary>
    public List<ProcessInfo> ScanAll()
    {
        var result = new List<ProcessInfo>();
        var wmiData = GetWmiProcessData();
        var processes = Process.GetProcesses();

        foreach (var proc in processes)
        {
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

                // Memory
                try { info.MemoryMB = proc.WorkingSet64 / (1024.0 * 1024.0); }
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

        _logger.Debug("ProcessScanner", $"Scanned {result.Count} processes");
        return result.OrderByDescending(p => p.MemoryMB).ToList();
    }

    /// <summary>
    /// Kill a process by PID with safety checks.
    /// </summary>
    public (bool Success, string Message) KillProcess(int pid)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            var name = proc.ProcessName;

            // Safety: never kill critical system processes
            if (IsProtectedProcess(name))
                return (false, $"Refused to kill protected process: {name}");

            proc.Kill(entireProcessTree: true);
            proc.WaitForExit(5000);
            _logger.Threat("ProcessScanner", $"Killed process {name} (PID {pid})");
            return (true, $"Killed {name} (PID {pid})");
        }
        catch (Exception ex)
        {
            _logger.Error("ProcessScanner", $"Failed to kill PID {pid}: {ex.Message}");
            return (false, ex.Message);
        }
    }

    /// <summary>
    /// Grabs CommandLine, ParentProcessId, and ExecutablePath from WMI for all processes.
    /// </summary>
    private Dictionary<int, WmiProcessInfo> GetWmiProcessData()
    {
        var dict = new Dictionary<int, WmiProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine, ParentProcessId, ExecutablePath FROM Win32_Process");
            foreach (var obj in searcher.Get())
            {
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
        catch (Exception ex)
        {
            _logger.Warning("ProcessScanner", $"WMI query failed: {ex.Message}");
        }
        return dict;
    }

    private static bool IsProtectedProcess(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower is "system" or "idle" or "csrss" or "wininit"
            or "winlogon" or "services" or "lsass" or "smss"
            or "registry" or "memorycompression";
    }

    private record WmiProcessInfo
    {
        public string CommandLine { get; init; } = string.Empty;
        public int ParentPid { get; init; }
        public string ParentName { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
    }
}
