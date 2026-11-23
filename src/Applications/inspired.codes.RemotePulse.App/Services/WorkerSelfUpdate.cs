using System;
using System.IO;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.RemotePulse.App.Services;

/// <summary>
/// The predefined "Update Worker" command: Scripts/Update-RemotePulseWorker.ps1, compiled into
/// the App. It hands the update to a one-shot OS job (a SYSTEM scheduled task on Windows, a
/// transient systemd unit on Linux) and returns at once, because the installer stops the very
/// Worker service the command runs inside.
/// </summary>
public static class WorkerSelfUpdate
{
    public const string ResourceName = "RemotePulse.App.Update-RemotePulseWorker.ps1";

    /// <summary>
    /// Always this mode: the script runs in-process in the Worker as SYSTEM / root, which is
    /// what lets it register the OS job and replace the Worker without asking for credentials.
    /// It refuses to run in any other context.
    /// </summary>
    public const ExecutionMode Mode = ExecutionMode.RunWithHighestLocalPrivileges;

    /// <summary>
    /// The script only checks and schedules (the update itself runs after it returns), so this
    /// covers a slow worker-version.json lookup with room to spare.
    /// </summary>
    public const int TimeoutSeconds = 120;

    private static readonly Lazy<string> _script = new(() =>
    {
        using Stream stream = typeof(WorkerSelfUpdate).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded resource '{ResourceName}' is missing from the App build.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    });

    public static string Script => _script.Value;
}
