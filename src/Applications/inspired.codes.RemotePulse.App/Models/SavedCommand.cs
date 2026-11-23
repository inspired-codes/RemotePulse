namespace InspiredCodes.RemotePulse.App.Models;

public class SavedCommand
{
    public string Script { get; set; } = string.Empty;
    public bool IsPinned { get; set; }
    public DateTime LastUsedUtc { get; set; } = DateTime.UtcNow;
}
