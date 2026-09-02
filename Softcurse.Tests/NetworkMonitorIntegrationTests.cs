using System.Net;
using System.Net.Sockets;
using Softcurse.Monitor;
using Softcurse.Shared.Logging;
using Xunit;

namespace Softcurse.Tests;

public sealed class NetworkMonitorIntegrationTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-network-{Guid.NewGuid():N}");

    [Fact]
    public void GetConnections_CorrelatesOwnedIpv4UdpBinding()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)socket.LocalEndPoint!).Port;
        using var logger = new BlackwatchLogger(Path.Combine(_root, "logs"));

        var process = new Softcurse.Shared.Models.ProcessInfo
        {
            Pid = Environment.ProcessId,
            FileHash = "fixture-hash",
            IsSigned = true,
            CompanyName = "Fixture Company"
        };
        using var monitor = new NetworkMonitor(logger);
        var connections = monitor.GetConnections(new Dictionary<int, Softcurse.Shared.Models.ProcessInfo>
        {
            [Environment.ProcessId] = process
        });

        var owned = Assert.Single(connections, connection =>
            connection.Protocol == "UDP" &&
            connection.AddressFamily == "IPv4" &&
            connection.Pid == Environment.ProcessId &&
            connection.LocalEndpoint.EndsWith($":{port}", StringComparison.Ordinal));
        Assert.Equal("fixture-hash", owned.ProcessFileHash);
        Assert.True(owned.ProcessIsSigned);
        Assert.Equal("Fixture Company", owned.ProcessCompanyName);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
