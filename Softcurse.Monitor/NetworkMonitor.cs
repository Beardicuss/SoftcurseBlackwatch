using System.Diagnostics;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>Collects IPv4/IPv6 TCP and UDP ownership with contextual evidence and bounded history.</summary>
public sealed class NetworkMonitor : IDisposable
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private readonly BlackwatchLogger _logger;
    private readonly ConnectionHistoryTracker _history = new();
    private readonly ReverseDnsCache _dns;
    private readonly NetworkReputationSet? _reputation;
    public TelemetryHealth LastHealth { get; private set; } = TelemetryHealth.Error("Network telemetry has not completed yet.");

    public NetworkMonitor(BlackwatchLogger logger, ReverseDnsCache? dns = null, NetworkReputationSet? reputation = null)
    {
        _logger = logger;
        _dns = dns ?? new ReverseDnsCache();
        _reputation = reputation;
    }

    public List<ConnectionInfo> GetConnections(IReadOnlyDictionary<int, ProcessInfo>? processes = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<ConnectionInfo>();
        var processNames = new Dictionary<int, string>();
        var failures = new List<string>();
        CollectSafely("IPv4 TCP", () => ReadTcp4().Select(row => CreateTcp(
            (int)row.OwnerPid, new IPAddress(row.LocalAddress), Port(row.LocalPort),
            new IPAddress(row.RemoteAddress), Port(row.RemotePort), row.State, "IPv4", processNames, processes)), result, failures, cancellationToken);
        CollectSafely("IPv6 TCP", () => ReadTcp6().Select(row => CreateTcp(
            (int)row.OwnerPid, new IPAddress(row.LocalAddress, row.LocalScopeId), Port(row.LocalPort),
            new IPAddress(row.RemoteAddress, row.RemoteScopeId), Port(row.RemotePort), row.State, "IPv6", processNames, processes)), result, failures, cancellationToken);
        CollectSafely("IPv4 UDP", () => ReadUdp4().Select(row => CreateUdp(
            (int)row.OwnerPid, new IPAddress(row.LocalAddress), Port(row.LocalPort), "IPv4", processNames, processes)), result, failures, cancellationToken);
        CollectSafely("IPv6 UDP", () => ReadUdp6().Select(row => CreateUdp(
            (int)row.OwnerPid, new IPAddress(row.LocalAddress, row.LocalScopeId), Port(row.LocalPort), "IPv6", processNames, processes)), result, failures, cancellationToken);
        LastHealth = failures.Count == 0
            ? TelemetryHealth.Healthy("Network telemetry is operational.")
            : TelemetryHealth.Degraded($"Network telemetry is incomplete: {string.Join("; ", failures)}");
        return result.OrderBy(item => item.Protocol).ThenBy(item => item.ProcessName).ThenBy(item => item.LocalEndpoint).ToList();
    }

    public List<string> GetListeners()
    {
        try
        {
            return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpListeners().Select(endpoint => endpoint.ToString()).ToList();
        }
        catch (Exception ex)
        {
            _logger.Warning("NetworkMonitor", $"Failed to enumerate listeners: {ex.Message}");
            return [];
        }
    }

    private void CollectSafely(string source, Func<IEnumerable<ConnectionInfo>> collect, ICollection<ConnectionInfo> result, ICollection<string> failures, CancellationToken cancellationToken)
    {
        try
        {
            foreach (var item in collect())
            {
                cancellationToken.ThrowIfCancellationRequested();
                result.Add(item);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            failures.Add($"{source}: {ex.Message}");
            _logger.Warning("NetworkMonitor", $"Failed to enumerate {source}: {ex.Message}");
        }
    }

    private ConnectionInfo CreateTcp(int pid, IPAddress localAddress, int localPort, IPAddress remoteAddress, int remotePort, uint state, string family, IDictionary<int, string> names, IReadOnlyDictionary<int, ProcessInfo>? processes)
    {
        var processName = ResolveProcessName(pid, names);
        ProcessInfo? process = null;
        if (processes is not null) processes.TryGetValue(pid, out process);
        var remoteHostName = _dns.GetCachedOrQueue(remoteAddress);
        var info = new ConnectionInfo
        {
            Pid = pid,
            Protocol = "TCP",
            AddressFamily = family,
            ProcessName = processName,
            LocalEndpoint = FormatEndpoint(localAddress, localPort),
            RemoteEndpoint = FormatEndpoint(remoteAddress, remotePort),
            RemoteHostName = remoteHostName,
            RemotePort = remotePort,
            State = Enum.IsDefined(typeof(TcpState), (int)state) ? ((TcpState)state).ToString() : $"Unknown({state})"
        };
        ApplyProcessIdentity(info, process);

        // Listening/unconnected rows do not have a meaningful remote endpoint and receive no remote verdict.
        if (remotePort > 0 && !remoteAddress.Equals(IPAddress.Any) && !remoteAddress.Equals(IPAddress.IPv6Any))
        {
            var assessment = NetworkEvidenceEvaluator.Evaluate(processName, remoteAddress, remotePort, process, remoteHostName, _reputation);
            info.IsSuspicious = assessment.IsSuspicious;
            info.Confidence = assessment.Confidence;
            info.Evidence = assessment.Evidence.ToList();
            info.SuspiciousReason = assessment.Reason;
            if (assessment.IsSuspicious)
                _logger.Threat("NetworkMonitor", $"Corroborated network evidence ({assessment.Confidence}) for {processName} (PID {pid}) to {remoteAddress}:{remotePort}");
        }
        _history.Observe(info, DateTime.UtcNow);
        return info;
    }

    private ConnectionInfo CreateUdp(int pid, IPAddress localAddress, int localPort, string family, IDictionary<int, string> names, IReadOnlyDictionary<int, ProcessInfo>? processes)
    {
        var info = new ConnectionInfo
        {
            Pid = pid,
            Protocol = "UDP",
            AddressFamily = family,
            ProcessName = ResolveProcessName(pid, names),
            LocalEndpoint = FormatEndpoint(localAddress, localPort),
            RemoteEndpoint = "—",
            RemotePort = 0,
            State = "Bound",
            SuspiciousReason = "UDP owner telemetry exposes a local binding only; no remote verdict is inferred."
        };
        if (processes is not null && processes.TryGetValue(pid, out var process)) ApplyProcessIdentity(info, process);
        _history.Observe(info, DateTime.UtcNow);
        return info;
    }

    private static string ResolveProcessName(int pid, IDictionary<int, string> cache)
    {
        if (cache.TryGetValue(pid, out var name)) return name;
        try { using var process = Process.GetProcessById(pid); name = process.ProcessName; }
        catch { name = pid == 0 ? "SYSTEM" : $"PID {pid}"; }
        cache[pid] = name;
        return name;
    }

    private static void ApplyProcessIdentity(ConnectionInfo connection, ProcessInfo? process)
    {
        if (process is null) return;
        connection.ProcessFileHash = process.FileHash;
        connection.ProcessIsSigned = process.IsSigned;
        connection.ProcessPublisherThumbprint = process.PublisherThumbprint;
        connection.ProcessCompanyName = process.CompanyName;
    }

    private static string FormatEndpoint(IPAddress address, int port) => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{address}]:{port}" : $"{address}:{port}";
    private static int Port(uint value) => (ushort)IPAddress.NetworkToHostOrder((short)value);

    private static List<Tcp4Row> ReadTcp4() => ReadTable<Tcp4Row>(AfInet, GetExtendedTcpTable, TcpTableOwnerPidAll);
    private static List<Tcp6Row> ReadTcp6() => ReadTable<Tcp6Row>(AfInet6, GetExtendedTcpTable, TcpTableOwnerPidAll);
    private static List<Udp4Row> ReadUdp4() => ReadTable<Udp4Row>(AfInet, GetExtendedUdpTable, UdpTableOwnerPid);
    private static List<Udp6Row> ReadUdp6() => ReadTable<Udp6Row>(AfInet6, GetExtendedUdpTable, UdpTableOwnerPid);

    private delegate uint TableReader(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);
    private static List<T> ReadTable<T>(int family, TableReader reader, int tableClass) where T : struct
    {
        var size = 0;
        var sizingResult = reader(IntPtr.Zero, ref size, true, family, tableClass, 0);
        if (sizingResult != 0 && sizingResult != 122) throw new Win32Exception((int)sizingResult);
        if (size < sizeof(int)) return [];
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var readResult = reader(buffer, ref size, true, family, tableClass, 0);
            if (readResult != 0) throw new Win32Exception((int)readResult);
            var count = Marshal.ReadInt32(buffer);
            var pointer = buffer + sizeof(int);
            var rowSize = Marshal.SizeOf<T>();
            var rows = new List<T>(Math.Max(0, count));
            for (var index = 0; index < count; index++, pointer += rowSize)
                rows.Add(Marshal.PtrToStructure<T>(pointer));
            return rows;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private enum TcpState { Closed = 1, Listen, SynSent, SynReceived, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, DeleteTcb }
    [StructLayout(LayoutKind.Sequential)] private struct Tcp4Row { public uint State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwnerPid; }
    [StructLayout(LayoutKind.Sequential)] private struct Udp4Row { public uint LocalAddress, LocalPort, OwnerPid; }
    [StructLayout(LayoutKind.Sequential)] private struct Tcp6Row
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId, LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] RemoteAddress;
        public uint RemoteScopeId, RemotePort, State, OwnerPid;
    }
    [StructLayout(LayoutKind.Sequential)] private struct Udp6Row
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] LocalAddress;
        public uint LocalScopeId, LocalPort, OwnerPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);
    [DllImport("iphlpapi.dll", SetLastError = true)] private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, int reserved);

    public void Dispose() => _dns.Dispose();
}
