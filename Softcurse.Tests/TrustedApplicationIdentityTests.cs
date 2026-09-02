using System.Security.Cryptography;
using Softcurse.Shared.Security;
using Xunit;

namespace Softcurse.Tests;

public sealed class TrustedApplicationIdentityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-trust-{Guid.NewGuid():N}");

    [Fact]
    public void Inspect_BindsCanonicalPathAndSha256()
    {
        Directory.CreateDirectory(_root);
        var executable = Path.Combine(_root, "fixture.exe");
        File.WriteAllText(executable, "fixture executable identity");
        var expectedHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))).ToLowerInvariant();

        var identity = TrustedApplicationIdentity.Inspect(executable, "test");

        Assert.Equal(Path.GetFullPath(executable), identity.CanonicalPath);
        Assert.Equal(expectedHash, identity.Sha256);
        Assert.Equal("fixture", identity.Name);
        Assert.Equal("test", identity.Reason);
        Assert.Equal(32, identity.TrustId.Length);
        Assert.True(identity.CreatedUtc <= DateTime.UtcNow);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
