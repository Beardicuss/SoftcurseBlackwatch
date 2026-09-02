using System.Text.RegularExpressions;

namespace Softcurse.Shared.Logging;

public static partial class LogRedactor
{
    public static string Redact(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var result = value.Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
        result = ReplaceKnownPath(result, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "%USERPROFILE%");
        result = ReplaceKnownPath(result, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "%LOCALAPPDATA%");
        result = ReplaceKnownPath(result, Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), "%TEMP%");
        result = SecretPattern().Replace(result, match => $"{match.Groups[1].Value}=[REDACTED]");
        result = UrlQueryPattern().Replace(result, match => $"{match.Groups[1].Value}?[REDACTED]");
        return result;
    }

    private static string ReplaceKnownPath(string value, string path, string replacement) =>
        string.IsNullOrWhiteSpace(path) ? value : value.Replace(path, replacement, StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex("""(?i)\b(password|passwd|token|secret|authorization|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)""")]
    private static partial Regex SecretPattern();

    [GeneratedRegex(@"(?i)\b(https?://[^\s?#]+(?:/[^\s?#]*)?)\?[^\s]+")]
    private static partial Regex UrlQueryPattern();
}
