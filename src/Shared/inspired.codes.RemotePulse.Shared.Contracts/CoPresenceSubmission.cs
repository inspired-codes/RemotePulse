namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Co-presence pairing v2 submission (see docs/specs/pairing-v2-key-binding-spec.md). Both the
/// Worker and the Mobile App POST this same shape to the Hub at /api/pairing/v2, distinguished
/// by Role ("Client" or "App"). <see cref="PairingId"/> is the HKDF-derived match key <c>pid</c>
/// (never the raw QR secret <c>S</c>). <see cref="AppBindTag"/> is the HMAC-SHA256 key-binding
/// tag required for Role=App and relayed opaquely to the Worker.
/// </summary>
public record CoPresenceSubmission(
    string PairingId = "",
    string Role = "",
    DateTimeOffset GeneratedAtUtc = default,
    string? MachineId = null,
    string? PublicKey = null,
    string? AppId = null,
    string? AppPublicKey = null,
    string? SecretSignature = null,
    string? AppBindTag = null)
{
    public CoPresenceSubmission() : this(string.Empty, string.Empty, default) { }
}
