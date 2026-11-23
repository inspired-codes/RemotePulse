using System.Runtime.InteropServices;

namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// Resolves where the Worker stores its private key and pairing state on each OS.
/// </summary>
public static class AppPaths
{
    private const string SystemWideLinuxPath = "/var/lib/remotepulse";

    /// <summary>
    /// Returns a data directory the running process can actually write to. On Windows this is
    /// unchanged (CommonApplicationData, e.g. C:\ProgramData\RemotePulse). On Linux/macOS,
    /// CommonApplicationData commonly resolves to a path an unprivileged process can't write to
    /// (e.g. under /usr/share) - this prefers /var/lib/remotepulse when the process can write
    /// there (typically true for a privileged systemd service or root), falling back to a
    /// per-user directory (~/.local/share/remotepulse) otherwise.
    /// </summary>
    public static string GetDataDirectory()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePulse");
        }

        if (CanWriteToDirectory(SystemWideLinuxPath))
        {
            return SystemWideLinuxPath;
        }

        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "remotepulse");
    }

    /// <summary>Convenience for the files this app actually stores.</summary>
    public static string GetKeyStoragePath() => Path.Combine(GetDataDirectory(), "client_key.dat");
    public static string GetPairingFilePath() => Path.Combine(GetDataDirectory(), "pairing.json");
    public static string GetLogFilePath() => Path.Combine(GetDataDirectory(), "worker.log");

    /// <summary>
    /// Bounded FIFO replay-protection ring for command envelopes (SEC-1). Persisted rather than
    /// in-memory so a Hub can't defeat it by simply waiting for a service restart.
    /// </summary>
    public static string GetExecutedCommandsFilePath() => Path.Combine(GetDataDirectory(), "executed-commands.json");

    private static bool CanWriteToDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            string probePath = Path.Combine(path, $".write-test-{Guid.NewGuid():N}");
            File.WriteAllText(probePath, string.Empty);
            File.Delete(probePath);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
