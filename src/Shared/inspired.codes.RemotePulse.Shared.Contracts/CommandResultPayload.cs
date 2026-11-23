namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// The sensitive inner payload of a CommandResult, encrypted end-to-end between Worker and App.
/// </summary>
public record CommandResultPayload(
    bool Success = false,
    double DurationMs = 0,
    string Output = "",
    string Error = "",
    string CombinedOutput = "",
    CommandStreams? Streams = null)
{
    public CommandResultPayload() : this(false) { }
}
