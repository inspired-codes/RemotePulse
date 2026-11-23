namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Identifies which Windows security context a Worker should execute a script under.
/// </summary>
public enum ExecutionMode
{
    /// <summary>
    /// Impersonates the active interactive desktop user's thread token. No UI capability —
    /// the process still runs in the Worker's own session, just under the user's identity
    /// for file/registry/ACL purposes.
    /// </summary>
    RunAsCurrentUser = 0,

    /// <summary>
    /// Launches a new process inside the active interactive user's session
    /// (<c>CreateProcessAsUser</c>, attached to <c>winsta0\default</c>). Required for anything
    /// that needs a visible desktop, such as a toast notification.
    /// </summary>
    RunInteractiveAsCurrentUser = 1,

    /// <summary>
    /// Runs directly as the Worker's own identity (typically <c>NT AUTHORITY\SYSTEM</c>), with
    /// no impersonation or session hop.
    /// </summary>
    RunWithHighestLocalPrivileges = 2
}
