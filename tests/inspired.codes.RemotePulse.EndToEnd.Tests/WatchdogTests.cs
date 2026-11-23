using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.EndToEnd.Tests;

/// <summary>
/// End-to-end liveness: a real Worker checking in against a real Hub is what flips the App's
/// availability indicator. Automates what was previously "start the service, watch the badge go
/// green, sc stop it, watch it go red".
/// </summary>
public class WatchdogTests
{
    [Fact]
    public async Task WorkerPollingForReal_ShouldFlipTheAppsWatchdogFeedToOnline()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        // Paired but never heard from - the App should not claim this machine is available.
        var before = await sut.GetClientStatusesAsync();
        var beforeStatus = Assert.Single(before);
        Assert.Equal(ClientHealth.Offline, beforeStatus.Health);
        Assert.Null(beforeStatus.LastSeenUtc);

        // A genuine Worker poll, going through real signature verification on the Hub.
        await sut.RunWorkerCycleAsync();

        var after = await sut.GetClientStatusesAsync();
        var afterStatus = Assert.Single(after);
        Assert.Equal(ClientHealth.Online, afterStatus.Health);
        Assert.Equal(0, afterStatus.MissedPolls);
        Assert.NotNull(afterStatus.LastSeenUtc);
        Assert.NotNull(afterStatus.SecondsSinceLastSeen);
        Assert.True(afterStatus.SecondsSinceLastSeen < 60);
    }

    [Fact]
    public async Task WorkerPoll_ShouldReportItsOwnCadenceSoTheThresholdSelfTunes()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        await sut.RunWorkerCycleAsync();

        // The fixture runs the Worker with pollIntervalSeconds: 30, and the real AddSignatureHeaders
        // is what puts that on the wire - so this proves the header is actually sent in production
        // code paths, not just that the Hub can parse one.
        Assert.Equal(30, await sut.GetStoredPollIntervalAsync());
    }

    [Fact]
    public async Task WorkerPoll_ShouldReportItsVersionThroughTheHubToTheApp()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        await sut.RunWorkerCycleAsync();

        // The real Worker's AddSignatureHeaders puts X-Worker-Version / X-Worker-Capabilities on
        // the wire, the real Hub stores them, and the App reads them back from the watchdog feed.
        // This pins the cross-component contract (header names, value format, normalization) that
        // the per-component tests can only check from one side each.
        var status = Assert.Single(await sut.GetClientStatusesAsync());
        Assert.Equal(InspiredCodes.RemotePulse.Worker.PollingWorker.WorkerVersion, status.WorkerVersion);
        Assert.Matches(@"^\d+\.\d+\.\d+$", status.WorkerVersion);

        // 1.2.0 supports nothing new yet, so it advertises an empty list - stored as "none".
        Assert.Null(status.Capabilities);
    }

    [Fact]
    public async Task ExecutingACommand_ShouldAlsoCountAsAHeartbeat()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        await sut.QueueCommandAsync("Write-Output 'hi'", ExecutionMode.RunWithHighestLocalPrivileges);
        await sut.RunWorkerCycleAsync();

        // Posting a result is an authenticated Worker request too, so liveness stays fresh even
        // for a Worker busy running long commands rather than idling on polls.
        var status = Assert.Single(await sut.GetClientStatusesAsync());
        Assert.Equal(ClientHealth.Online, status.Health);
    }
}
