using System.Diagnostics;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.EndToEnd.Tests;

/// <summary>
/// The behaviour long-polling exists for: a script sent from the App starts running on the Worker
/// within a second or so, instead of waiting out a poll interval.
/// </summary>
public class LongPollingTests
{
    [Fact]
    public async Task CommandQueuedWhileTheWorkerIsParked_ShouldRunWithoutWaitingOutTheWindow()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        // The Worker parks on an empty queue with a 30s window. If long-polling did not work,
        // this cycle would return empty and the command would sit unexecuted.
        var stopwatch = Stopwatch.StartNew();
        Task cycle = sut.RunWorkerCycleAsync(longPollWaitSeconds: 30);

        // Let the poll actually reach the Hub and park before anything is queued.
        await Task.Delay(300);

        string commandId = await sut.QueueCommandAsync(
            "Write-Output 'LONG-POLL-MARKER'",
            ExecutionMode.RunWithHighestLocalPrivileges);

        await cycle;
        stopwatch.Stop();

        var rawResult = await sut.GetResultAsync(commandId);
        Assert.NotNull(rawResult);
        Assert.True(rawResult.IsEncrypted);

        var result = await sut.GetDecryptedResultAsync(commandId);
        Assert.NotNull(result);
        Assert.True(result.Success, $"Expected success. Error was: {result.Error}");
        Assert.Contains("LONG-POLL-MARKER", result.Output);

        // The window was 30s. Anything near that means the command was found by the timeout
        // rather than delivered on the signal - which is the whole feature failing quietly.
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(15),
            $"Command took {stopwatch.Elapsed.TotalSeconds:F1}s end to end; expected near-immediate delivery.");
    }

    [Fact]
    public async Task AParkedWorkerShouldStillReadAsOnline()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        // A Worker parked on a long poll sends no new heartbeat until the window closes. It
        // reports the wait window as its cadence precisely so the Hub grades it against that
        // rather than against the much shorter poll interval - otherwise sitting idle and
        // healthy would look like several missed check-ins.
        await sut.RunWorkerCycleAsync(longPollWaitSeconds: 1);

        var status = Assert.Single(await sut.GetClientStatusesAsync());
        Assert.Equal(ClientHealth.Online, status.Health);
        Assert.Equal(1, await sut.GetStoredPollIntervalAsync());
    }

    [Fact]
    public async Task AnEmptyQueueShouldReturnQuietlyOnceTheWindowCloses()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        // Nothing queued and nothing signalled: the cycle should end on its own at the window,
        // not hang or throw.
        var stopwatch = Stopwatch.StartNew();
        await sut.RunWorkerCycleAsync(longPollWaitSeconds: 1);
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed >= TimeSpan.FromMilliseconds(900), "Expected the poll to hold for its window.");
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), "Expected the poll to give up promptly after it.");
    }
}
