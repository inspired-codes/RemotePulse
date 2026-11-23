using System.Text.Json;

namespace InspiredCodes.RemotePulse.Worker;

/// <summary>
/// SEC-1 replay protection: the command envelopes this Worker has already executed, persisted to
/// executed-commands.json so a restart doesn't reopen the replay window - a malicious or
/// compromised Hub could otherwise just wait for one.
/// </summary>
/// <remarks>
/// An entry is kept for <see cref="Retention"/> after execution, measured on this Worker's own
/// clock - the same clock the 5-minute freshness check uses. An envelope accepted at time T was
/// issued within 5 minutes of T, so it fails the freshness check by T + 10 minutes at the latest;
/// until then its entry is guaranteed to still be here. (A fixed cap of the newest 500 entries,
/// used before, could evict a still-fresh envelope if more than 500 ran within 5 minutes.) There
/// is no count cap: only envelopes that passed signature verification are recorded, so the file
/// grows only as fast as the paired App actually sends commands.
/// </remarks>
public sealed class ExecutedCommandStore
{
    /// <summary>Twice the 5-minute freshness window - see the class remarks.</summary>
    public static readonly TimeSpan Retention = TimeSpan.FromMinutes(10);

    private readonly string _path;
    private readonly ILogger _logger;
    private readonly Func<DateTimeOffset> _utcNow;

    public ExecutedCommandStore(string path, ILogger logger, Func<DateTimeOffset>? utcNow = null)
    {
        _path = path;
        _logger = logger;
        _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    }

    public bool Contains(string commandId, string nonce)
    {
        string key = Key(commandId, nonce);
        return Load().Any(e => e.Key == key);
    }

    /// <summary>
    /// Marks the envelope as executed. Call only once it has passed signature verification, so a
    /// malformed or forged envelope can't poison the store and block a legitimate retry of the same
    /// (CommandId, Nonce) that never actually ran.
    /// </summary>
    public void Record(string commandId, string nonce)
    {
        DateTimeOffset now = _utcNow();
        List<Entry> entries = Load();

        // Age only - never count. An entry "from the future" (the clock was stepped back since it
        // was written) is kept: its envelope may well still be fresh.
        entries.RemoveAll(e => now - e.RecordedAtUtc > Retention);
        entries.Add(new Entry(Key(commandId, nonce), now));

        string? dir = Path.GetDirectoryName(_path);
        if (dir != null && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        File.WriteAllText(_path, JsonSerializer.Serialize(entries));
    }

    private List<Entry> Load()
    {
        if (!File.Exists(_path)) return new List<Entry>();
        try
        {
            using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(_path));
            var entries = new List<Entry>();
            foreach (JsonElement element in doc.RootElement.EnumerateArray())
            {
                if (element.ValueKind == JsonValueKind.String)
                {
                    // Format up to Worker 1.1.1: bare keys with no time. Treat them as executed just
                    // now, so they're kept for a full Retention after the upgrade.
                    entries.Add(new Entry(element.GetString()!, _utcNow()));
                }
                else if (element.Deserialize<Entry>() is { Key.Length: > 0 } entry)
                {
                    entries.Add(entry);
                }
            }
            return entries;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "executed-commands.json at {Path} could not be parsed; treating as empty (replay protection reset).", _path);
            return new List<Entry>();
        }
    }

    private static string Key(string commandId, string nonce) => $"{commandId}:{nonce}";

    private sealed record Entry(string Key, DateTimeOffset RecordedAtUtc);
}
