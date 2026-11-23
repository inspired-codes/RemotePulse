namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Authenticated pairing release request sent by Worker to Hub Server on unpair.
/// </summary>
public record ReleasePairingRequest(string? AppId);
