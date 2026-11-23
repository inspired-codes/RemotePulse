namespace InspiredCodes.RemotePulse.App.Models;

/// <summary>
/// Outcome of <see cref="Services.AppState.AddPairedClientAsync"/>.
/// </summary>
/// <remarks>
/// A pairing is always accepted and stored, never rejected for being over the worker limit. By
/// the time this runs, the Hub has already matched the co-presence secret and locked the
/// pairing, and the Worker learns of it independently on its own next poll cycle - refusing to
/// remember it locally would just orphan a pairing that is already cryptographically real on
/// both sides, recoverable only by walking back to that Worker's own local onboarding page.
/// <see cref="AddedOverLimit"/> instead tells the caller the count is now past
/// <see cref="Services.AppState.MaxPairedClients"/>, so the UI can prompt the operator to pick
/// one to drop - always resolvable from the phone that just did the pairing.
/// </remarks>
public enum AddClientResult
{
    /// <summary>A new client was added, at or under the limit.</summary>
    Added,

    /// <summary>An already-paired client (same MachineId) was refreshed - re-pairing, not new.</summary>
    Updated,

    /// <summary>A new client was added and it pushed the paired count past the limit.</summary>
    AddedOverLimit
}
