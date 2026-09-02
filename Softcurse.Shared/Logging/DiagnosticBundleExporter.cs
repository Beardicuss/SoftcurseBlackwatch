using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace Softcurse.Shared.Logging;

public sealed record DiagnosticSummary(
    string ProductVersion,
    string HealthLevel,
    string HealthMessage,
    DateTime? LastSuccessfulScanUtc,
    bool DryRunMode,
    int ProcessCount,
    int ThreatCount,
    int ConnectionCount);

public static class DiagnosticBundleExporter
{
    public static void Export(string destinationPath, string logDirectory, DiagnosticSummary summary)
    {
        if (!Path.IsPathFullyQualified(destinationPath)) throw new ArgumentException("Diagnostic destination must be absolute.", nameof(destinationPath));
        var destinationDirectory = Path.GetDirectoryName(destinationPath) ?? throw new ArgumentException("Diagnostic destination has no directory.", nameof(destinationPath));
        Directory.CreateDirectory(destinationDirectory);
        var temporaryPath = Path.Combine(destinationDirectory, $".{Path.GetFileName(destinationPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
            {
                var summaryEntry = archive.CreateEntry("diagnostic-summary.json", CompressionLevel.Optimal);
                using (var writer = new StreamWriter(summaryEntry.Open(), new UTF8Encoding(false)))
                {
                    writer.Write(JsonSerializer.Serialize(new
                    {
                        generatedUtc = DateTime.UtcNow,
                        summary.ProductVersion,
                        summary.HealthLevel,
                        healthMessage = LogRedactor.Redact(summary.HealthMessage),
                        summary.LastSuccessfulScanUtc,
                        summary.DryRunMode,
                        summary.ProcessCount,
                        summary.ThreatCount,
                        summary.ConnectionCount,
                        operatingSystem = Environment.OSVersion.VersionString,
                        runtime = Environment.Version.ToString(),
                        architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString()
                    }, new JsonSerializerOptions { WriteIndented = true }));
                }

                if (Directory.Exists(logDirectory))
                {
                    foreach (var logPath in Directory.EnumerateFiles(logDirectory, "blackwatch_*.log", SearchOption.TopDirectoryOnly).Order())
                    {
                        var info = new FileInfo(logPath);
                        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        var logEntry = archive.CreateEntry($"logs/{info.Name}", CompressionLevel.Optimal);
                        using var input = new StreamReader(logPath, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        using var output = new StreamWriter(logEntry.Open(), new UTF8Encoding(false));
                        while (input.ReadLine() is { } line) output.WriteLine(LogRedactor.Redact(line));
                    }
                }
            }
            File.Move(temporaryPath, destinationPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }
}
