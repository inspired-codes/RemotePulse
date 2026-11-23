namespace InspiredCodes.RemotePulse.App.Models;

/// <summary>Outcome of <see cref="Services.HubApiClient.SubmitCoPresenceAsync"/>.</summary>
public enum PairingSubmitResult
{
    /// <summary>The Hub round trip failed, or its response was malformed. Nothing was paired.</summary>
    Failed,

    /// <summary>
    /// The Hub returned a <c>clientPublicKey</c> whose SHA-256 fingerprint did not match the
    /// <c>fp</c> parameter from the Worker's QR code. Pairing was aborted locally without saving.
    /// </summary>
    FingerprintMismatch,

    /// <summary>Paired (new or re-paired), at or under the worker limit.</summary>
    Paired,

    /// <summary>
    /// Paired, but this pushed the device's paired-worker count past <see cref="Services.AppState.MaxPairedClients"/>.
    /// The pairing is real and stored (see <see cref="AddClientResult.AddedOverLimit"/>) - the UI
    /// should prompt the operator to pick one of the paired workers to drop.
    /// </summary>
    PairedOverLimit
}
