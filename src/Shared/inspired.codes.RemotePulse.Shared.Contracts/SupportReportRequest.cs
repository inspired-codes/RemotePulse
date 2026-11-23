namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// A free-text problem report submitted before any signed identity exists - e.g. an
/// Installer failure prior to pairing, or a manual report from the public portal page.
/// POSTed to the Hub's /api/support/report, which is deliberately unauthenticated: the Hub's
/// rate limiting, the proxy's body-size cap and server-side length caps are the guardrails instead of a signature
/// check, since the whole point is this has to work when nothing else can.
/// </summary>
public class SupportReportRequest
{
    /// <summary>Where the report originated: "Installer" or "Web".</summary>
    public string Source { get; set; } = string.Empty;

    /// <summary>The error message or a short user-written description. Capped server-side.</summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// The machine's MachineId, if one had already been minted by the time of the failure.
    /// Null when reported before that point in the install.
    /// </summary>
    public string? MachineId { get; set; }

    /// <summary>
    /// Structured diagnostics (OS, PowerShell version, failed step, etc.) serialized as JSON.
    /// </summary>
    public string? DetailsJson { get; set; }

    /// <summary>
    /// Optional explicit severity: "Information", "Warning", or "Error". When omitted, the Hub
    /// falls back to inferring it from <see cref="Source"/> (installer reports default to
    /// "Error") - which is wrong for a success/confirmation report from the same source, hence
    /// this field. A caller that knows its own severity (e.g. a successful-install confirmation)
    /// should always set it explicitly rather than rely on the fallback.
    /// </summary>
    public string? LogLevel { get; set; }
}
