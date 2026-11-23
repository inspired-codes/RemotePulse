namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// How healthy a paired machine's heartbeat looks, graded by how many expected check-ins it has
/// missed rather than by a single online/offline cutoff.
/// </summary>
/// <remarks>
/// The middle grade is the point of this: a Worker that has missed a poll or two is usually
/// mid-reboot, on flaky WiFi, or busy - visibly different from one that has genuinely stopped,
/// but not yet worth calling dead. A plain boolean forced those two situations to look identical.
/// </remarks>
public enum ClientHealth
{
    /// <summary>Checked in as expected - no missed confirmations.</summary>
    Online = 0,

    /// <summary>One or two missed confirmations: something may be wrong, but not conclusively.</summary>
    Degraded = 1,

    /// <summary>Three or more missed confirmations, or never checked in at all.</summary>
    Offline = 2
}
