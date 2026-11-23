namespace InspiredCodes.RemotePulse.App.Models;

public class PairedClient
{
    public string MachineId { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty; // Base64 SPKI EC P-256 Public Key
    public string ServerUrl { get; set; } = string.Empty;
    public string Alias { get; set; } = string.Empty;
}
