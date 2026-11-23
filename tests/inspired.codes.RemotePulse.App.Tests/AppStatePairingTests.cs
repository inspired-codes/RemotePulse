using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.App.Services;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// The free-tier 3-worker limit: <see cref="AppState.AddPairedClientAsync"/> must never reject a
/// pairing - by the time it runs, the Hub has already matched it and the Worker will learn of it
/// independently, so rejecting here would just orphan a real pairing. It only ever reports
/// whether the addition pushed the count over the limit, for the UI to react to.
/// </summary>
public class AppStatePairingTests
{
    private readonly AppState _appState;

    public AppStatePairingTests()
    {
        var js = new FakeJSRuntime();
        _appState = new AppState(new LocalStorageService(js), new CryptoService(js));
    }

    private static PairedClient Client(string machineId) => new()
    {
        MachineId = machineId,
        PublicKey = "pub-" + machineId,
        ServerUrl = "https://hub.example.test",
        Alias = machineId
    };

    [Fact]
    public async Task AddPairedClientAsync_UnderLimit_ReturnsAdded()
    {
        var result = await _appState.AddPairedClientAsync(Client("PC-1"));

        Assert.Equal(AddClientResult.Added, result);
        Assert.Single(_appState.PairedClients);
    }

    [Fact]
    public async Task AddPairedClientAsync_AtExactlyMaxLimit_StillReturnsAdded()
    {
        await _appState.AddPairedClientAsync(Client("PC-1"));
        await _appState.AddPairedClientAsync(Client("PC-2"));
        var result = await _appState.AddPairedClientAsync(Client("PC-3"));

        Assert.Equal(AddClientResult.Added, result);
        Assert.Equal(AppState.MaxPairedClients, _appState.PairedClients.Count);
        Assert.False(_appState.CanPairNewClient);
    }

    [Fact]
    public async Task AddPairedClientAsync_PastMaxLimit_IsAcceptedAndFlaggedOverLimit()
    {
        await _appState.AddPairedClientAsync(Client("PC-1"));
        await _appState.AddPairedClientAsync(Client("PC-2"));
        await _appState.AddPairedClientAsync(Client("PC-3"));
        var result = await _appState.AddPairedClientAsync(Client("PC-4"));

        // The whole point: never rejected. The 4th pairing is real (Hub/Worker already locked
        // it) and must be stored, just flagged so the UI can prompt to drop one.
        Assert.Equal(AddClientResult.AddedOverLimit, result);
        Assert.Equal(4, _appState.PairedClients.Count);
        Assert.Contains(_appState.PairedClients, c => c.MachineId == "PC-4");
    }

    [Fact]
    public async Task AddPairedClientAsync_RePairingExistingMachine_ReturnsUpdated_EvenOverLimit()
    {
        await _appState.AddPairedClientAsync(Client("PC-1"));
        await _appState.AddPairedClientAsync(Client("PC-2"));
        await _appState.AddPairedClientAsync(Client("PC-3"));
        await _appState.AddPairedClientAsync(Client("PC-4")); // now over limit, 4 paired

        var updated = Client("PC-2");
        updated.PublicKey = "rotated-key";
        var result = await _appState.AddPairedClientAsync(updated);

        Assert.Equal(AddClientResult.Updated, result);
        Assert.Equal(4, _appState.PairedClients.Count); // unchanged count - not a new entry
        Assert.Equal("rotated-key", _appState.PairedClients.Single(c => c.MachineId == "PC-2").PublicKey);
    }

    [Fact]
    public async Task CanPairNewClient_TrueBelowLimit_FalseAtLimit()
    {
        Assert.True(_appState.CanPairNewClient);

        await _appState.AddPairedClientAsync(Client("PC-1"));
        await _appState.AddPairedClientAsync(Client("PC-2"));
        Assert.True(_appState.CanPairNewClient);

        await _appState.AddPairedClientAsync(Client("PC-3"));
        Assert.False(_appState.CanPairNewClient);
    }

    [Fact]
    public async Task ExportAndImport_PairedClientsJson_ShouldRoundtripSuccessfully()
    {
        await _appState.AddPairedClientAsync(Client("PC-1"));
        await _appState.AddPairedClientAsync(Client("PC-2"));

        string exportedJson = _appState.ExportPairedClientsJson();
        Assert.Contains("PC-1", exportedJson);
        Assert.Contains("PC-2", exportedJson);

        var js2 = new FakeJSRuntime();
        var secondState = new AppState(new LocalStorageService(js2), new CryptoService(js2));
        int importedCount = await secondState.ImportPairedClientsJsonAsync(exportedJson);

        Assert.Equal(2, importedCount);
        Assert.Equal(2, secondState.PairedClients.Count);
        Assert.Equal("PC-1", secondState.PairedClients[0].MachineId);
        Assert.Equal("PC-2", secondState.PairedClients[1].MachineId);
    }

    [Fact]
    public async Task InitializeAsync_WhenPairedClientsJsonCorrupt_SavesBackupAndLeavesEmpty()
    {
        var js = new FakeJSRuntime();
        var storage = new LocalStorageService(js);
        await storage.SetItemAsync("remotepulse_paired_clients", "{ not valid json [");

        var appState = new AppState(storage, new CryptoService(js));
        await appState.InitializeAsync();

        Assert.Empty(appState.PairedClients);
        string? backup = await storage.GetItemAsync("remotepulse_paired_clients_corrupt_backup");
        Assert.Equal("{ not valid json [", backup);
    }
}
