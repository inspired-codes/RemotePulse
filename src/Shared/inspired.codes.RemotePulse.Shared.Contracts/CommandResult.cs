namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Execution output details posted by Worker back to Hub Server.
/// In Phase 1 E2EE, sensitive outputs (Output, Error, CombinedOutput, Streams)
/// are encrypted in EncryptedPayload and populated on the App only after decryption.
/// </summary>
public record CommandResult(
    string CommandId = "",
    bool Success = false,
    double DurationMs = 0,
    bool IsEncrypted = true,
    string? EncryptedPayload = null,
    string? RejectionReason = null,
    string Output = "",
    string Error = "",
    string CombinedOutput = "",
    CommandStreams? Streams = null)
{
    public CommandResult() : this(string.Empty) { }
}
