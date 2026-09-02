using System.IO;
using System.Reflection;
using Softcurse.Shared.Security;

namespace Softcurse.UI;

internal static class InstallationSelfTest
{
    internal static int Run()
    {
        try
        {
            var assembly = typeof(App).Assembly;
            if (!string.Equals(assembly.GetName().Name, "Softcurse.Blackwatch", StringComparison.Ordinal))
                return 10;

            var baseDirectory = AppContext.BaseDirectory;
            var requiredFiles = new[]
            {
                "Softcurse.Blackwatch.exe",
                "Softcurse.Blackwatch.dll",
                "Softcurse.Blackwatch.deps.json",
                "Softcurse.Blackwatch.runtimeconfig.json",
                "WebView2Loader.dll",
                Path.Combine("Assets", "app.ico"),
                Path.Combine("Assets", "blackwatch-logo.png"),
                Path.Combine("WebUI", "index.html"),
            };

            if (requiredFiles.Any(path => !File.Exists(Path.Combine(baseDirectory, path))))
                return 11;

            var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.Equals(version, "0.1.0-alpha", StringComparison.Ordinal))
                return 12;

            using var manifest = assembly.GetManifestResourceStream("Softcurse.UI.WebUI.sha256");
            if (manifest is null)
                return 13;

            var result = WebUiIntegrityVerifier.Verify(Path.Combine(baseDirectory, "WebUI"), manifest);
            return result.Success ? 0 : 14;
        }
        catch
        {
            return 99;
        }
    }
}
