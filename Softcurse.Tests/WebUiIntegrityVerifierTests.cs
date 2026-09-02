using System.Security.Cryptography;
using System.Text;
using Softcurse.Shared.Security;
using Xunit;

namespace Softcurse.Tests;

public sealed class WebUiIntegrityVerifierTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-webui-{Guid.NewGuid():N}");

    [Fact]
    public void Verify_AcceptsExactFileSetAndHashes()
    {
        Write("index.html", "<html>fixture</html>");
        Write(Path.Combine("assets", "app.js"), "console.log('fixture');");

        var result = Verify(ManifestFor("index.html", Path.Combine("assets", "app.js")));

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, result.VerifiedFileCount);
    }

    [Fact]
    public void Verify_RejectsModifiedFile()
    {
        Write("index.html", "original");
        var manifest = ManifestFor("index.html");
        Write("index.html", "modified");

        var result = Verify(manifest);

        Assert.False(result.Success);
        Assert.Contains("integrity mismatch", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsMissingFile()
    {
        Write("index.html", "fixture");
        var manifest = ManifestFor("index.html");
        File.Delete(Path.Combine(_root, "index.html"));

        var result = Verify(manifest);

        Assert.False(result.Success);
        Assert.Contains("Missing", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsUnexpectedFile()
    {
        Write("index.html", "fixture");
        var manifest = ManifestFor("index.html");
        Write("injected.js", "malicious");

        var result = Verify(manifest);

        Assert.False(result.Success);
        Assert.Contains("Unexpected", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsDuplicateManifestPath()
    {
        Write("index.html", "fixture");
        var record = ManifestFor("index.html").TrimEnd();

        var result = Verify(record + Environment.NewLine + record);

        Assert.False(result.Success);
        Assert.Contains("duplicate", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsPathTraversal()
    {
        Write("index.html", "fixture");
        var hash = new string('a', 64);

        var result = Verify($"{hash}|../outside.js");

        Assert.False(result.Success);
        Assert.Contains("unsafe path", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_RejectsMalformedHash()
    {
        Write("index.html", "fixture");

        var result = Verify($"{new string('z', 64)}|index.html");

        Assert.False(result.Success);
        Assert.Contains("invalid SHA-256", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    private WebUiIntegrityResult Verify(string manifest)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(manifest));
        return WebUiIntegrityVerifier.Verify(_root, stream);
    }

    private string ManifestFor(params string[] relativePaths) => string.Join(
        Environment.NewLine,
        relativePaths.Select(relativePath =>
        {
            var bytes = File.ReadAllBytes(Path.Combine(_root, relativePath));
            return $"{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}|{relativePath.Replace('\\', '/')}";
        }));

    private void Write(string relativePath, string content)
    {
        var path = Path.Combine(_root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
