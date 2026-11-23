using System;
using System.IO;
using Microsoft.Extensions.Logging;
using Xunit;

namespace InspiredCodes.RemotePulse.Worker.Tests;

public class FileLoggerProviderTests : IDisposable
{
    private readonly string _dir;
    private readonly string _logPath;

    public FileLoggerProviderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"filelogger_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _logPath = Path.Combine(_dir, "worker.log");
    }

    [Fact]
    public void ClearLogFile_TruncatesLogAndRemovesRotatedFile()
    {
        File.WriteAllText(_logPath, "old line\n");
        File.WriteAllText(_logPath + ".old", "rotated\n");

        FileLoggerProvider.ClearLogFile(_logPath);

        Assert.Equal(string.Empty, File.ReadAllText(_logPath));
        Assert.False(File.Exists(_logPath + ".old"));
    }

    [Fact]
    public void Sink_DropsRoutineHttpClientInformation_ButKeepsWarnings()
    {
        using ILoggerFactory factory = LoggerFactory.Create(b => b.AddProvider(new FileLoggerProvider(_logPath)));
        ILogger http = factory.CreateLogger("System.Net.Http.HttpClient.RemotePulseHub.LogicalHandler");
        ILogger worker = factory.CreateLogger("InspiredCodes.RemotePulse.Worker.PollingWorker");

        http.LogInformation("Start processing HTTP request");
        http.LogWarning("Request failed with 500");
        worker.LogInformation("Command received");

        string content = File.ReadAllText(_logPath);
        Assert.DoesNotContain("Start processing HTTP request", content);
        Assert.Contains("Request failed with 500", content);
        Assert.Contains("Command received", content);
    }

    [Theory]
    [InlineData("2026-10-02 10:00:00.000 [Information] System.Net.Http.HttpClient.RemotePulseHub.ClientHandler: Received HTTP response - 204", true)]
    [InlineData("2026-10-02 10:00:00.000 [Debug] Microsoft.AspNetCore.Hosting.Diagnostics: Request starting", true)]
    [InlineData("2026-10-02 10:00:00.000 [Warning] System.Net.Http.HttpClient.RemotePulseHub.ClientHandler: Received HTTP response - 500", false)]
    [InlineData("2026-10-02 10:00:00.000 [Information] InspiredCodes.RemotePulse.Worker.PollingWorker: Command received", false)]
    public void IsPollingNoise_ClassifiesByLevelAndCategory(string line, bool expected)
    {
        Assert.Equal(expected, FileLoggerProvider.IsPollingNoise(line));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }
}
