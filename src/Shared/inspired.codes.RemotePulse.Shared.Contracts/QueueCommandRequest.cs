namespace InspiredCodes.RemotePulse.Shared.Contracts;

/// <summary>
/// Command queuing request submitted by Mobile App to Hub Server.
/// </summary>
public record QueueCommandRequest(
    string MachineId = "",
    string EncryptedScript = "",
    ExecutionMode ExecutionMode = ExecutionMode.RunAsCurrentUser,
    string CommandId = "",
    int? TimeoutSeconds = null)
{
    public QueueCommandRequest() : this(string.Empty, string.Empty, ExecutionMode.RunAsCurrentUser, string.Empty) { }
}
