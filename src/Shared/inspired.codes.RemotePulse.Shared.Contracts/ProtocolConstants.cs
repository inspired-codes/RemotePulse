namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Constants for wire protocol negotiation and version checking.
/// </summary>
public static class ProtocolConstants
{
    /// <summary>
    /// Header name used by clients and server to signal protocol version.
    /// </summary>
    public const string VersionHeaderName = "X-Protocol-Version";

    /// <summary>
    /// Current protocol version string.
    /// </summary>
    public const string CurrentVersion = "1";

    /// <summary>
    /// Current protocol version integer for numeric comparisons.
    /// </summary>
    public const int CurrentVersionNumber = 1;

    /// <summary>
    /// Header on every signed Worker request (Worker 1.2.0+) carrying the Worker's own version.
    /// </summary>
    public const string WorkerVersionHeaderName = "X-Worker-Version";

    /// <summary>
    /// Header on every signed Worker request (Worker 1.2.0+) carrying a comma-separated list of
    /// <see cref="WorkerCapabilityTokens"/>. Informational only: it isn't covered by the request
    /// signature, so it may steer what the App offers, never what is safe to send.
    /// </summary>
    public const string WorkerCapabilitiesHeaderName = "X-Worker-Capabilities";
}

/// <summary>
/// Feature tokens a Worker advertises in <see cref="ProtocolConstants.WorkerCapabilitiesHeaderName"/>.
/// Lowercase, <c>[a-z0-9-]</c>. Readers ignore tokens they don't know.
/// </summary>
public static class WorkerCapabilityTokens
{
    /// <summary>Accepts command envelope v2.</summary>
    public const string EnvelopeV2 = "envelope-v2";

    /// <summary>Binds typed <c>Parameters</c> from a v2 envelope.</summary>
    public const string Params = "params";

    /// <summary>Handles <c>Kind: "preflight"</c> (validate only, never execute).</summary>
    public const string Preflight = "preflight";
}
