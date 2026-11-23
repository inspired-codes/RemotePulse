namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Liveness of one paired machine, as evaluated by the Hub Server.
/// SecondsSinceLastSeen and Health are computed Hub-side to prevent phone clock skew issues.
/// WorkerVersion and Capabilities are what the Worker last self-reported (Worker 1.2.0+; null for
/// older Workers). They only decide which features the App offers - see
/// <see cref="WorkerCapabilityTokens"/>.
/// </summary>
public record ClientStatus(
    string MachineId = "",
    DateTime? LastSeenUtc = null,
    double? SecondsSinceLastSeen = null,
    ClientHealth Health = ClientHealth.Offline,
    int? MissedPolls = null,
    bool HubUnreachable = false,
    string? WorkerVersion = null,
    IReadOnlyList<string>? Capabilities = null)
{
    public ClientStatus() : this(string.Empty) { }
}
