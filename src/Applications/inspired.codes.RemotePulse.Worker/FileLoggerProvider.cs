namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// Windows Event Log entries from this Worker's own categories (PollingWorker, LocalUiServer,
/// KeyPairManager, etc.) never actually show up in the Application log - only the framework's
/// own WindowsServiceLifetime "Service started/stopped successfully" lines do, even though
/// Logging:LogLevel:Default is set to Information. Rather than chase that further, this plain
/// file sink gives a reliable, easy-to-tail place to see what the poll loop is actually doing
/// when running as a service with no attached console.
/// </summary>
public sealed class FileLoggerProvider(string filePath) : ILoggerProvider
{
    /// <summary>
    /// Shared by every writer and by <see cref="ClearLogFile"/>, so a clear can never interleave
    /// with an in-flight append.
    /// </summary>
    private static readonly object SyncLock = new();

    /// <summary>
    /// Categories whose routine chatter (long-poll 204s, ASP.NET hosting noise) is dropped below
    /// Warning before it ever reaches disk.
    /// </summary>
    private static readonly string[] NoisyCategoryPrefixes = ["System.Net.Http.HttpClient", "Microsoft.AspNetCore"];

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, filePath);

    public void Dispose()
    {
    }

    public static void ClearLogFile(string filePath)
    {
        lock (SyncLock)
        {
            if (File.Exists(filePath))
            {
                File.WriteAllText(filePath, string.Empty);
            }

            string rotated = filePath + ".old";
            if (File.Exists(rotated))
            {
                File.Delete(rotated);
            }
        }
    }

    /// <summary>
    /// True for a formatted log line that is routine polling/hosting chatter (Trace, Debug or
    /// Information from a noisy category). Warnings and above are never noise.
    /// </summary>
    public static bool IsPollingNoise(string line)
    {
        if (!line.Contains("[Information]") && !line.Contains("[Debug]") && !line.Contains("[Trace]"))
        {
            return false;
        }

        foreach (string prefix in NoisyCategoryPrefixes)
        {
            if (line.Contains("] " + prefix))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsNoisyCategory(string categoryName) =>
        NoisyCategoryPrefixes.Any(prefix => categoryName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    private sealed class FileLogger(string categoryName, string filePath) : ILogger
    {
        private const long MaxBytesBeforeRotate = 5 * 1024 * 1024;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            logLevel != LogLevel.None && !(logLevel < LogLevel.Warning && IsNoisyCategory(categoryName));

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            string line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{logLevel}] {categoryName}: {formatter(state, exception)}";
            if (exception != null)
            {
                line += Environment.NewLine + exception;
            }

            lock (SyncLock)
            {
                try
                {
                    string? dir = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    if (File.Exists(filePath) && new FileInfo(filePath).Length > MaxBytesBeforeRotate)
                    {
                        File.Copy(filePath, filePath + ".old", overwrite: true);
                        File.Delete(filePath);
                    }

                    File.AppendAllText(filePath, line + Environment.NewLine);
                }
                catch
                {
                    // Logging must never crash the worker it's trying to observe.
                }
            }
        }
    }
}
