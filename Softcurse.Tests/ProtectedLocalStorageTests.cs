using System.Security.AccessControl;
using System.Security.Principal;
using Softcurse.Shared.Security;
using Xunit;

namespace Softcurse.Tests;

public sealed class ProtectedLocalStorageTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), $"blackwatch-acl-{Guid.NewGuid():N}");

    [Fact]
    public void EnsurePrivateDirectory_ProtectsInheritanceAndGrantsCurrentUser()
    {
        if (!OperatingSystem.IsWindows()) return;

        ProtectedLocalStorage.EnsurePrivateDirectory(_root);

        var security = new DirectoryInfo(_root).GetAccessControl();
        var currentUser = WindowsIdentity.GetCurrent().User;
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToList();
        Assert.True(security.AreAccessRulesProtected);
        Assert.Contains(rules, rule =>
            Equals(rule.IdentityReference, currentUser) &&
            rule.AccessControlType == AccessControlType.Allow &&
            rule.FileSystemRights.HasFlag(FileSystemRights.FullControl));
        Assert.DoesNotContain(rules, rule => rule.IsInherited);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
