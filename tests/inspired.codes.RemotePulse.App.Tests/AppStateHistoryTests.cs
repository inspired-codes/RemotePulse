using InspiredCodes.RemotePulse.App.Services;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

public class AppStateHistoryTests
{
    private readonly FakeJSRuntime _js;
    private readonly AppState _appState;

    public AppStateHistoryTests()
    {
        _js = new FakeJSRuntime();
        var storage = new LocalStorageService(_js);
        var crypto = new CryptoService(_js);
        _appState = new AppState(storage, crypto);
    }

    [Fact]
    public async Task AddScriptToHistoryAsync_AddsItemToFrontAndDeduplicates()
    {
        await _appState.AddScriptToHistoryAsync("Get-Process");
        await _appState.AddScriptToHistoryAsync("Get-Service");
        await _appState.AddScriptToHistoryAsync("Get-Process");

        Assert.Equal(2, _appState.CommandHistory.Count);
        Assert.Equal("Get-Process", _appState.CommandHistory[0].Script);
        Assert.Equal("Get-Service", _appState.CommandHistory[1].Script);
    }

    [Fact]
    public async Task TogglePinScriptAsync_PinsItemToTop()
    {
        await _appState.AddScriptToHistoryAsync("cmd1");
        await _appState.AddScriptToHistoryAsync("cmd2");
        await _appState.AddScriptToHistoryAsync("cmd3");

        // Initially: cmd3 (0), cmd2 (1), cmd1 (2)
        // Pin cmd1 (index 2)
        await _appState.TogglePinScriptAsync(2);

        // Pinned item should now be on top at index 0
        Assert.True(_appState.CommandHistory[0].IsPinned);
        Assert.Equal("cmd1", _appState.CommandHistory[0].Script);

        // Unpin cmd1
        await _appState.TogglePinScriptAsync(0);
        Assert.False(_appState.CommandHistory[0].IsPinned);
    }

    [Fact]
    public async Task RemoveScriptFromHistoryAsync_ByIndex_RemovesCorrectItem()
    {
        await _appState.AddScriptToHistoryAsync("cmd1");
        await _appState.AddScriptToHistoryAsync("cmd2");
        await _appState.AddScriptToHistoryAsync("cmd3");

        // History order is cmd3 (0), cmd2 (1), cmd1 (2)
        await _appState.RemoveScriptFromHistoryAsync(1);

        Assert.Equal(2, _appState.CommandHistory.Count);
        Assert.Equal("cmd3", _appState.CommandHistory[0].Script);
        Assert.Equal("cmd1", _appState.CommandHistory[1].Script);
    }

    [Fact]
    public async Task ClearCommandHistoryAsync_UnpinnedOnly_KeepsPinnedItems()
    {
        await _appState.AddScriptToHistoryAsync("unpinned1");
        await _appState.AddScriptToHistoryAsync("pinned1");
        await _appState.TogglePinScriptAsync(0); // Pin "pinned1"

        await _appState.ClearCommandHistoryAsync(unpinnedOnly: true);

        Assert.Single(_appState.CommandHistory);
        Assert.Equal("pinned1", _appState.CommandHistory[0].Script);
        Assert.True(_appState.CommandHistory[0].IsPinned);
    }

    [Fact]
    public async Task ClearCommandHistoryAsync_EmptiesAllHistory()
    {
        await _appState.AddScriptToHistoryAsync("cmd1");
        await _appState.AddScriptToHistoryAsync("cmd2");

        await _appState.ClearCommandHistoryAsync();

        Assert.Empty(_appState.CommandHistory);
    }
}
