using InspiredCodes.RemotePulse.App.Services;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

public class AppStateLogTests
{
    private static AppState NewState()
    {
        var js = new FakeJSRuntime();
        return new AppState(new LocalStorageService(js), new CryptoService(js));
    }

    [Fact]
    public void Log_AppearsInBothConsoleAndUploadedLog()
    {
        var state = NewState();

        state.Log("Posting command to queue...");

        Assert.Contains("Posting command to queue...", state.ConsoleOutput);
        Assert.Contains("Posting command to queue...", state.DiagnosticOutput);
    }

    [Fact]
    public void LogResultContent_ShowsContentInConsole_OnlyLabelInUploadedLog()
    {
        var state = NewState();

        state.LogResultContent("Success Output:", "line one\nline two");

        Assert.Contains("Success Output:\nline one\nline two", state.ConsoleOutput);
        Assert.Contains("Success Output: [withheld from uploaded logs]", state.DiagnosticOutput);
        Assert.DoesNotContain("line one", state.DiagnosticOutput);
    }

    [Fact]
    public async Task RenameClient_ShowsTheNameInConsole_ButNotInUploadedLog()
    {
        var state = NewState();
        await state.AddPairedClientAsync(new Models.PairedClient { MachineId = "0c3b62fd-b76e-42c0-8b07-c6b76956d4b4", ServerUrl = "https://hub.example.test" });

        await state.RenameClientAsync("0c3b62fd-b76e-42c0-8b07-c6b76956d4b4", "Reception PC");

        Assert.Contains("Renamed client to: Reception PC", state.ConsoleOutput);
        Assert.DoesNotContain("Reception", state.DiagnosticOutput);
        Assert.Contains("Renamed machine 0c3b62fd (new name withheld from uploaded logs)", state.DiagnosticOutput);
    }

    [Theory]
    [InlineData("0c3b62fd-b76e-42c0-8b07-c6b76956d4b4", "machine 0c3b62fd")]
    [InlineData("PC-1", "machine PC-1")]
    public void UploadMachineName_UsesAnIdPrefixNeverTheAlias(string machineId, string expected)
    {
        Assert.Equal(expected, AppState.UploadMachineName(machineId));
    }

    [Fact]
    public void ClearConsole_ClearsUploadedLogToo()
    {
        var state = NewState();
        state.Log("before clear");

        state.ClearConsole();

        Assert.DoesNotContain("before clear", state.ConsoleOutput);
        Assert.DoesNotContain("before clear", state.DiagnosticOutput);
    }
}
