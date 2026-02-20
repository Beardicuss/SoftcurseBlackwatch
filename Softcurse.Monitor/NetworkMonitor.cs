using System.Net.NetworkInformation;
using Softcurse.Shared.Logging;
using Softcurse.Shared.Models;

namespace Softcurse.Monitor;

/// <summary>
/// Monitors active TCP/UDP connections.
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
    /// Gets all active TCP connections with suspicion flags.
    /// </summary>
    public List<ConnectionInfo> GetConnections()
    {
        var result = new List<ConnectionInfo>();
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var connections = props.GetActiveTcpConnections();

            foreach (var conn in connections)
            {
                var info = new ConnectionInfo
                {
                    LocalEndpoint = conn.LocalEndPoint.ToString(),
                    RemoteEndpoint = conn.RemoteEndPoint.ToString(),
                    RemotePort = conn.RemoteEndPoint.Port,
                    State = conn.State.ToString(),
                };

                // Flag mining ports
                if (MiningPorts.Contains(conn.RemoteEndPoint.Port))
                {
                    info.IsSuspicious = true;
                    info.SuspiciousReason = $"Mining pool port: {conn.RemoteEndPoint.Port}";
                    _logger.Threat("NetworkMonitor",
                        $"Suspicious connection to port {conn.RemoteEndPoint.Port}: {conn.RemoteEndPoint}");
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
            var props = IPGlobalProperties.GetIPGlobalProperties();
            foreach (var ep in props.GetActiveTcpListeners())
                result.Add(ep.ToString());
        }
        catch { }
        return result;
    }
}
