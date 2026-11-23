namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Structured command payload dispatched from Hub Server to Worker.
/// </summary>
public record ServerCommand(
    string CommandId = "",
    string Script = "",
    ExecutionMode ExecutionMode = ExecutionMode.RunAsCurrentUser,
    bool IsHandshake = false,
    int? TimeoutSeconds = null)
{
    public ServerCommand() : this(string.Empty, string.Empty, ExecutionMode.RunAsCurrentUser) { }
}
