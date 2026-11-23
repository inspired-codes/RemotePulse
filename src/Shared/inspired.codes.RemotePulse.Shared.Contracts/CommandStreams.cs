namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Detailed PowerShell execution streams and diagnostics.
/// </summary>
public record CommandStreams(
    IReadOnlyList<string>? Warnings = null,
    IReadOnlyList<string>? Errors = null,
    IReadOnlyList<string>? Information = null,
    IReadOnlyList<string>? Verbose = null,
    IReadOnlyList<string>? Debug = null,
    string? ExceptionDetails = null)
{
    public CommandStreams() : this(null, null, null, null, null, null) { }
}
