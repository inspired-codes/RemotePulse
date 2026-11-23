using System.Text.Json;
using System.Text.Json.Serialization;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.RemotePulse.App.Services;

public class AppState
{
    public static readonly JsonSerializerOptions StorageJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly LocalStorageService _storage;
    private readonly CryptoService _crypto;

    public event Action? OnStateChanged;

    public string AppId { get; set; } = string.Empty;
    public string AppPublicKeyBase64 { get; set; } = string.Empty;
    public string ServerUrl { get; set; } = "http://localhost:5000";
    public bool IsPwaBypassed { get; set; } = false;
    public string Theme { get; set; } = "dark";

    public List<Models.PairedClient> PairedClients { get; set; } = new();
    public Models.PairedClient? ActiveClient { get; set; }
    public List<Models.SavedCommand> CommandHistory { get; set; } = new();

    /// <summary>
    /// Free-tier cap on how many distinct Workers this Mobile App instance manages. Enforced
    /// entirely here, client-side - the Hub and Worker have no concept of it (Worker<->Mobile
    /// stays 1:1 regardless; this only bounds how many Workers one Mobile pairs with). See
    /// <see cref="Models.AddClientResult"/> for how a pairing that exceeds this is still honored,
    /// never silently dropped.
    /// </summary>
    public const int MaxPairedClients = 3;

    /// <summary>Whether initiating a brand new pairing is currently under the free-tier cap. A
    /// UI hint only - re-pairing an already-known MachineId is always allowed regardless, and
    /// scanning a pairing link directly (bypassing the in-app scanner) can't be gated on this at
    /// all, so <see cref="AddPairedClientAsync"/> still has to accept an over-cap result rather
    /// than assume this was checked first.</summary>
    public bool CanPairNewClient => PairedClients.Count < MaxPairedClients;

    /// <summary>
    /// Live per-machine availability, keyed by MachineId, refreshed by <c>ClientWatchdog</c>.
    /// Deliberately NOT persisted to localStorage: liveness is point-in-time, and restoring a
    /// stale "online" on app launch would be worse than showing nothing at all.
    /// </summary>
    public Dictionary<string, ClientStatus> ClientStatuses { get; } = new();

    /// <summary>
    /// True once the watchdog has completed at least one cycle, so the UI can tell
    /// "still checking" apart from "checked, and there's nothing to report".
    /// </summary>
    public bool HasWatchdogResult { get; set; }

    /// <summary>
    /// Whether the App's last attempt to reach the Hub succeeded. Null until the watchdog has
    /// run once. This is the middle link of App -> Hub -> Worker: false here (with the device
    /// online) means the Hub itself is down or unreachable, not the Worker.
    /// </summary>
    public bool? HubReachable { get; set; }

    /// <summary>
    /// Browser connectivity (<c>navigator.onLine</c>). When false, an unreachable Hub is just
    /// the phone being offline - not a Hub or Worker fault - so the UI can say so plainly.
    /// </summary>
    public bool DeviceOnline { get; set; } = true;

    /// <summary>
    /// Returns the known status for a machine, or a HubUnreachable placeholder if the watchdog
    /// hasn't managed to report on it yet.
    /// </summary>
    public ClientStatus GetClientStatus(string machineId)
    {
        if (ClientStatuses.TryGetValue(machineId, out var status))
        {
            return status;
        }
        return new ClientStatus { MachineId = machineId, HubUnreachable = true };
    }

    public string ConsoleOutput { get; private set; } = "System idle. Pair a client to start sending commands.";

    /// <summary>The console as Send Log uploads it: decrypted result content replaced by its label.</summary>
    public string DiagnosticOutput { get; private set; } = "System idle. Pair a client to start sending commands.";
    public bool IsAwaitingCommandResult { get; set; } = false;

    public AppState(LocalStorageService storage, CryptoService crypto)
    {
        _storage = storage;
        _crypto = crypto;
    }

    public async Task InitializeAsync()
    {
        // Load App ID & Keys
        string? storedAppId = await _storage.GetItemAsync("remotepulse_app_id");
        string? storedPubKey = await _storage.GetItemAsync("remotepulse_app_pub_key");

        bool hasCachedIdentity = !string.IsNullOrEmpty(storedAppId) && !string.IsNullOrEmpty(storedPubKey);
        bool identityLost = false;

        // localStorage and IndexedDB are separate stores - a cached App ID/public key here is
        // not proof the matching private key still exists in IndexedDB. Verify before trusting
        // it, or every sign attempt later fails with "Private key not found in IndexedDB"
        // instead of recovering.
        if (hasCachedIdentity && await _crypto.HasPrivateKeyAsync())
        {
            AppId = storedAppId!;
            AppPublicKeyBase64 = storedPubKey!;
            Log("Existing App keys loaded successfully.");
        }
        else
        {
            identityLost = hasCachedIdentity;
            if (identityLost)
            {
                Log("Stored App identity found, but its private key is missing from secure storage (likely lost to a storage clear). Generating a new identity - any previously paired clients will need to be re-paired.");
            }
            await GenerateNewAppKeysAsync();
        }

        // Load Paired Clients. If the App just got a new identity above (private key was lost),
        // any previously paired clients are now cryptographically stale - the Worker only
        // recognizes the old AppId/public key, so every signed request would fail anyway. Clear
        // them so the UI honestly shows "not paired" instead of a "Paired & Locked" badge that
        // can never actually work again.
        if (identityLost)
        {
            PairedClients = new();
            await _storage.SetItemAsync("remotepulse_paired_clients", JsonSerializer.Serialize(PairedClients, StorageJsonOptions));
        }
        else
        {
            string? clientsJson = await _storage.GetItemAsync("remotepulse_paired_clients");
            if (!string.IsNullOrEmpty(clientsJson))
            {
                try
                {
                    PairedClients = JsonSerializer.Deserialize<List<Models.PairedClient>>(clientsJson, StorageJsonOptions) ?? new();
                }
                catch (Exception ex)
                {
                    Log($"[WARNING] Failed to parse saved paired clients ({ex.Message}). Preserving raw backup in storage.");
                    await _storage.SetItemAsync("remotepulse_paired_clients_corrupt_backup", clientsJson);
                    PairedClients = new();
                }
            }
        }

        if (ActiveClient == null && PairedClients.Count > 0)
        {
            ActiveClient = PairedClients[0];
            ServerUrl = ActiveClient.ServerUrl;
        }

        // Load Command History
        string? historyJson = await _storage.GetItemAsync("remotepulse_command_history");
        if (!string.IsNullOrEmpty(historyJson))
        {
            try
            {
                CommandHistory = JsonSerializer.Deserialize<List<Models.SavedCommand>>(historyJson) ?? new();
            }
            catch
            {
                try
                {
                    var legacy = JsonSerializer.Deserialize<List<string>>(historyJson);
                    if (legacy != null)
                    {
                        CommandHistory = legacy
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .Select(s => new Models.SavedCommand { Script = s, IsPinned = false, LastUsedUtc = DateTime.UtcNow })
                            .ToList();
                    }
                }
                catch
                {
                    CommandHistory = new();
                }
            }
            SortCommandHistory();
        }

        NotifyStateChanged();
    }

    public async Task GenerateNewAppKeysAsync()
    {
        Log("Generating new App ECDSA P-256 signing keys...");
        AppId = Guid.NewGuid().ToString();
        var pubKey = await _crypto.GenerateAppKeysAsync();
        AppPublicKeyBase64 = pubKey;

        await _storage.SetItemAsync("remotepulse_app_id", AppId);
        await _storage.SetItemAsync("remotepulse_app_pub_key", pubKey);

        Log("App ECDSA keys generated and stored successfully (private key in IndexedDB).");
        NotifyStateChanged();
    }

    /// <summary>
    /// Records a pairing the Hub has already matched. Always accepts it - see
    /// <see cref="Models.AddClientResult"/> for why a pairing over <see cref="MaxPairedClients"/>
    /// is stored rather than rejected.
    /// </summary>
    public async Task<Models.AddClientResult> AddPairedClientAsync(Models.PairedClient client)
    {
        var existing = PairedClients.FirstOrDefault(c => c.MachineId == client.MachineId);
        Models.AddClientResult result;
        if (existing == null)
        {
            PairedClients.Add(client);
            result = PairedClients.Count > MaxPairedClients ? Models.AddClientResult.AddedOverLimit : Models.AddClientResult.Added;
            Log(result == Models.AddClientResult.AddedOverLimit
                ? $"Registered new paired client: {client.MachineId} ({PairedClients.Count}/{MaxPairedClients} - over this device's worker limit)"
                : $"Registered new paired client: {client.MachineId}");
        }
        else
        {
            existing.PublicKey = client.PublicKey;
            existing.ServerUrl = client.ServerUrl;
            result = Models.AddClientResult.Updated;
            Log($"Updated existing paired client: {client.MachineId}");
        }

        ActiveClient = client;
        await _storage.SetItemAsync("remotepulse_paired_clients", JsonSerializer.Serialize(PairedClients, StorageJsonOptions));
        NotifyStateChanged();
        return result;
    }

    public async Task UnpairClientAsync(string machineId)
    {
        PairedClients.RemoveAll(c => c.MachineId == machineId);
        await _storage.SetItemAsync("remotepulse_paired_clients", JsonSerializer.Serialize(PairedClients, StorageJsonOptions));
        Log($"Unpaired client computer: {machineId}");

        if (ActiveClient?.MachineId == machineId)
        {
            ActiveClient = null;
        }
        NotifyStateChanged();
    }

    public async Task RenameClientAsync(string machineId, string newAlias)
    {
        var client = PairedClients.FirstOrDefault(c => c.MachineId == machineId);
        if (client == null || string.IsNullOrWhiteSpace(newAlias)) return;

        client.Alias = newAlias.Trim();
        await _storage.SetItemAsync("remotepulse_paired_clients", JsonSerializer.Serialize(PairedClients, StorageJsonOptions));
        Log($"Renamed client to: {client.Alias}", $"Renamed {UploadMachineName(machineId)} (new name withheld from uploaded logs)");
        NotifyStateChanged();
    }

    /// <summary>
    /// Exports the non-secret paired clients configuration list as JSON.
    /// Note: The App's private key is non-extractable in WebCrypto by design and cannot be exported.
    /// This export saves the machine list, server URLs, and aliases for configuration backup.
    /// </summary>
    public string ExportPairedClientsJson()
    {
        return JsonSerializer.Serialize(PairedClients, new JsonSerializerOptions { WriteIndented = true });
    }

    /// <summary>
    /// Imports paired clients configuration. Merges new machines into existing pairings without overwriting.
    /// </summary>
    public async Task<int> ImportPairedClientsJsonAsync(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return 0;
        try
        {
            var imported = JsonSerializer.Deserialize<List<Models.PairedClient>>(json, StorageJsonOptions);
            if (imported == null || imported.Count == 0) return 0;

            int addedCount = 0;
            foreach (var client in imported)
            {
                if (string.IsNullOrWhiteSpace(client.MachineId)) continue;
                if (!PairedClients.Any(c => c.MachineId == client.MachineId))
                {
                    PairedClients.Add(client);
                    addedCount++;
                }
            }

            if (addedCount > 0)
            {
                await _storage.SetItemAsync("remotepulse_paired_clients", JsonSerializer.Serialize(PairedClients, StorageJsonOptions));
                if (ActiveClient == null && PairedClients.Count > 0)
                {
                    ActiveClient = PairedClients[0];
                    ServerUrl = ActiveClient.ServerUrl;
                }
                Log($"Imported {addedCount} paired client configuration(s).");
                NotifyStateChanged();
            }
            return addedCount;
        }
        catch (Exception ex)
        {
            Log($"Failed to import paired clients configuration: {ex.Message}");
            return 0;
        }
    }

    public void SelectActiveClient(string? machineId)
    {
        ActiveClient = PairedClients.FirstOrDefault(c => c.MachineId == machineId);
        if (ActiveClient != null)
        {
            ServerUrl = ActiveClient.ServerUrl;
            Log($"Selected active client: {ActiveClient.MachineId}");
        }
        else
        {
            Log("Deselected active client.");
        }
        NotifyStateChanged();
    }

    public async Task AddScriptToHistoryAsync(string scriptText)
    {
        if (string.IsNullOrWhiteSpace(scriptText)) return;

        var existing = CommandHistory.FirstOrDefault(s => s.Script.Trim() == scriptText.Trim());
        if (existing != null)
        {
            existing.LastUsedUtc = DateTime.UtcNow;
        }
        else
        {
            CommandHistory.Add(new Models.SavedCommand
            {
                Script = scriptText,
                IsPinned = false,
                LastUsedUtc = DateTime.UtcNow
            });
        }

        // Keep all pinned items + up to 15 recent unpinned items
        var pinned = CommandHistory.Where(c => c.IsPinned).ToList();
        var unpinned = CommandHistory.Where(c => !c.IsPinned).OrderByDescending(c => c.LastUsedUtc).Take(15).ToList();
        CommandHistory = pinned.Concat(unpinned).ToList();

        SortCommandHistory();
        await _storage.SetItemAsync("remotepulse_command_history", JsonSerializer.Serialize(CommandHistory));
        NotifyStateChanged();
    }

    public async Task TogglePinScriptAsync(int index)
    {
        if (index >= 0 && index < CommandHistory.Count)
        {
            CommandHistory[index].IsPinned = !CommandHistory[index].IsPinned;
            SortCommandHistory();
            await _storage.SetItemAsync("remotepulse_command_history", JsonSerializer.Serialize(CommandHistory));
            NotifyStateChanged();
        }
    }

    public async Task RemoveScriptFromHistoryAsync(int index)
    {
        if (index >= 0 && index < CommandHistory.Count)
        {
            CommandHistory.RemoveAt(index);
            await _storage.SetItemAsync("remotepulse_command_history", JsonSerializer.Serialize(CommandHistory));
            NotifyStateChanged();
        }
    }

    public async Task ClearCommandHistoryAsync(bool unpinnedOnly = false)
    {
        if (unpinnedOnly)
        {
            CommandHistory.RemoveAll(c => !c.IsPinned);
        }
        else
        {
            CommandHistory.Clear();
        }
        await _storage.SetItemAsync("remotepulse_command_history", JsonSerializer.Serialize(CommandHistory));
        NotifyStateChanged();
    }

    private void SortCommandHistory()
    {
        CommandHistory = CommandHistory
            .OrderByDescending(c => c.IsPinned)
            .ThenByDescending(c => c.LastUsedUtc)
            .ToList();
    }

    private const int MaxLogLines = 200;

    public void Log(string message) => Append(message, message);

    /// <summary>
    /// Logs a line whose console text names something only this device knows - a user-chosen
    /// machine name. <see cref="DiagnosticOutput"/>, which Send Log uploads, gets
    /// <paramref name="uploadMessage"/> instead.
    /// </summary>
    public void Log(string message, string uploadMessage) => Append(message, uploadMessage);

    /// <summary>
    /// How an uploaded log refers to a machine: a MachineId prefix, which the Hub already knows,
    /// rather than the alias the user gave it on this device.
    /// </summary>
    public static string UploadMachineName(string machineId) =>
        $"machine {(machineId.Length > 8 ? machineId[..8] : machineId)}";

    /// <summary>
    /// Logs decrypted command result content (output, error text, streams). It shows in
    /// <see cref="ConsoleOutput"/> on this device only; <see cref="DiagnosticOutput"/>, which
    /// Send Log uploads to the Hub, gets just the label - results are end-to-end encrypted,
    /// and an uploaded log must not hand the Hub the plaintext.
    /// </summary>
    public void LogResultContent(string label, string content) =>
        Append($"{label}\n{content}", $"{label} [withheld from uploaded logs]");

    private void Append(string consoleMessage, string diagnosticMessage)
    {
        string timestamp = DateTime.UtcNow.ToString("HH:mm:ss") + "Z";
        ConsoleOutput = CapLines(ConsoleOutput + $"\n[{timestamp}] {consoleMessage}");
        DiagnosticOutput = CapLines(DiagnosticOutput + $"\n[{timestamp}] {diagnosticMessage}");
        NotifyStateChanged();
    }

    // Cap log to avoid unbounded memory growth
    private static string CapLines(string log)
    {
        var lines = log.Split('\n');
        return lines.Length > MaxLogLines ? string.Join('\n', lines[^MaxLogLines..]) : log;
    }

    public void ClearConsole()
    {
        ConsoleOutput = "Console output cleared.";
        DiagnosticOutput = ConsoleOutput;
        NotifyStateChanged();
    }

    public void NotifyStateChanged() => OnStateChanged?.Invoke();
}
