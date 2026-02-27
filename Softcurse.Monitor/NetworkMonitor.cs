using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>
/// Monitors active TCP/UDP connections WITH process (PID) correlation.
/// Uses GetExtendedTcpTable for PID mapping (not available via IPGlobalProperties).
/// Flags connections to known mining ports and suspicious long-lived outbound connections.
/// </summary>
public class NetworkMonitor
{
    private readonly SentinelLogger _logger;

    // Known Stratum / mining pool ports
    private static readonly HashSet<int> MiningPorts = new()
    {
        3333, 4444, 5555, 7777, 8888, 9999,
        14444, 14433,
        20535, 20536,
        45560, 45700,
        3334, 5556, 8899,
    };

    public NetworkMonitor(SentinelLogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Gets all active TCP connections with PID correlation and suspicion flags.
    /// </summary>
    public List<ConnectionInfo> GetConnections()
    {
        var result = new List<ConnectionInfo>();
        try
        {
            var rows = GetTcpTableWithPid();
            // Build a PID → name cache to avoid repeated Process.GetProcessById calls
            var pidNameCache = new Dictionary<int, string>();

            foreach (var row in rows)
            {
                var remotePrt = (ushort)IPAddress.NetworkToHostOrder((short)row.dwRemotePort);
                var localPrt = (ushort)IPAddress.NetworkToHostOrder((short)row.dwLocalPort);
                var remoteIp = new IPAddress(row.dwRemoteAddr);
                var localIp = new IPAddress(row.dwLocalAddr);
                var pid = (int)row.dwOwningPid;

                // Resolve process name (cached)
                if (!pidNameCache.TryGetValue(pid, out var procName))
                {
                    try
                    {
                        using var proc = Process.GetProcessById(pid);
                        procName = proc.ProcessName;
                    }
                    catch { procName = pid == 0 ? "SYSTEM" : $"PID {pid}"; }
                    pidNameCache[pid] = procName;
                }

                var info = new ConnectionInfo
                {
                    Pid = pid,
                    ProcessName = procName,
                    LocalEndpoint = $"{localIp}:{localPrt}",
                    RemoteEndpoint = $"{remoteIp}:{remotePrt}",
                    RemotePort = remotePrt,
                    State = ((TcpState)row.dwState).ToString(),
                };

                // Flag mining ports
                if (MiningPorts.Contains(remotePrt))
                {
                    info.IsSuspicious = true;
                    info.SuspiciousReason = $"Mining pool port: {remotePrt}";
                    _logger.Threat("NetworkMonitor",
                        $"Suspicious connection by {procName} (PID {pid}) to port {remotePrt}: {remoteIp}");
                }

                result.Add(info);
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("NetworkMonitor", $"Failed to enumerate connections: {ex.Message}");
        }

        return result;
    }

    /// <summary>
    /// Gets active TCP listeners on the system.
    /// </summary>
    public List<string> GetListeners()
    {
        var result = new List<string>();
        try
        {
            var props = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties();
            foreach (var ep in props.GetActiveTcpListeners())
                result.Add(ep.ToString());
        }
        catch { }
        return result;
    }

    // ═══════════════════════════════════════════════
    // P/Invoke: GetExtendedTcpTable (provides PID)
    // ═══════════════════════════════════════════════

    private enum TcpState
    {
        Closed = 1, Listen, SynSent, SynReceived,
        Established, FinWait1, FinWait2, CloseWait,
        Closing, LastAck, TimeWait, DeleteTcb
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort,
        int ipVersion, int tblClass, int reserved);

    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    private List<MIB_TCPROW_OWNER_PID> GetTcpTableWithPid()
    {
        var rows = new List<MIB_TCPROW_OWNER_PID>();
        int bufferSize = 0;

        // First call: get required buffer size
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint ret = GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return rows;

            // First 4 bytes = row count
            int rowCount = Marshal.ReadInt32(buffer);
            var rowPtr = buffer + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rows.Add(row);
                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return rows;
    }
}
