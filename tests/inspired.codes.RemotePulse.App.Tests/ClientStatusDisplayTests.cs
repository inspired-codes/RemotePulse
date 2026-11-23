using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// The badge/dot mapping. The distinction that matters most here is "offline" vs
/// "hub unreachable" - collapsing those into one red state would blame the client PC for the
/// phone's own connectivity, which is exactly the confusion the watchdog exists to remove.
/// </summary>
public class ClientStatusDisplayTests
{
    [Fact]
    public void OnlineClient_ShouldRenderAsConnected()
    {
        var status = new ClientStatus { Health = ClientHealth.Online, MissedPolls = 0, LastSeenUtc = DateTime.UtcNow, SecondsSinceLastSeen = 5 };
        Assert.Equal("online", ClientStatusDisplay.DotClass(status));
        Assert.Equal("Online", ClientStatusDisplay.BadgeText(status, hasWatchdogResult: true));
        Assert.Equal("Last seen just now", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Fact]
    public void DegradedClient_ShouldRenderAmberAndSayHowManyCheckInsWereMissed()
    {
        var status = new ClientStatus { Health = ClientHealth.Degraded, MissedPolls = 2, LastSeenUtc = DateTime.UtcNow.AddSeconds(-35), SecondsSinceLastSeen = 35 };

        // Amber, not red: two missed check-ins is a warning, not a verdict.
        Assert.Equal("degraded", ClientStatusDisplay.DotClass(status));
        Assert.Equal("Unstable", ClientStatusDisplay.BadgeText(status, hasWatchdogResult: true));
        Assert.Equal("Last seen 35s ago - missed 2 check-ins.", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Fact]
    public void DegradedClientWithOneMiss_ShouldUseTheSingularForm()
    {
        var status = new ClientStatus { Health = ClientHealth.Degraded, MissedPolls = 1, LastSeenUtc = DateTime.UtcNow.AddSeconds(-20), SecondsSinceLastSeen = 20 };

        Assert.Equal("Last seen 20s ago - missed 1 check-in.", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Fact]
    public void OfflineClient_ShouldRenderAsDisconnectedWithItsAge()
    {
        var status = new ClientStatus { Health = ClientHealth.Offline, MissedPolls = 60, LastSeenUtc = DateTime.UtcNow.AddMinutes(-12), SecondsSinceLastSeen = 720 };
        Assert.Equal("offline", ClientStatusDisplay.DotClass(status));
        Assert.Equal("Offline", ClientStatusDisplay.BadgeText(status, hasWatchdogResult: true));
        Assert.Equal("Last seen 12m ago", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Fact]
    public void HubUnreachable_ShouldRenderNeutrallyRatherThanAsOffline()
    {
        var status = new ClientStatus { HubUnreachable = true };

        // Neutral, not red: we genuinely don't know the client's state.
        Assert.Equal("unknown", ClientStatusDisplay.DotClass(status));
        Assert.Equal("Hub Unreachable", ClientStatusDisplay.BadgeText(status, hasWatchdogResult: true));
        Assert.Contains("unknown", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Fact]
    public void BeforeTheFirstWatchdogCycle_ShouldSayCheckingRatherThanAccusingTheHub()
    {
        var status = new ClientStatus { HubUnreachable = true };

        Assert.Equal("Checking...", ClientStatusDisplay.BadgeText(status, hasWatchdogResult: false));
        Assert.Contains("Checking", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: false));
    }

    [Fact]
    public void WorkerVersionText_ShowsTheReportedVersion_AndNothingWithoutAFreshReport()
    {
        Assert.Equal("Worker 1.2.0", ClientStatusDisplay.WorkerVersionText(new ClientStatus { Health = ClientHealth.Online, WorkerVersion = "1.2.0" }));

        // Pre-1.2.0 Workers report nothing; an unreachable Hub means the report isn't fresh.
        Assert.Equal(string.Empty, ClientStatusDisplay.WorkerVersionText(new ClientStatus { Health = ClientHealth.Online }));
        Assert.Equal(string.Empty, ClientStatusDisplay.WorkerVersionText(new ClientStatus { HubUnreachable = true, WorkerVersion = "1.2.0" }));
    }

    [Fact]
    public void NeverSeenClient_ShouldSaySoRatherThanShowingAnAge()
    {
        var status = new ClientStatus { Health = ClientHealth.Offline, LastSeenUtc = null, SecondsSinceLastSeen = null, MissedPolls = null };
        Assert.Equal("Never checked in since it was registered.", ClientStatusDisplay.Tooltip(status, hasWatchdogResult: true));
    }

    [Theory]
    [InlineData(0, "just now")]
    [InlineData(9.9, "just now")]
    [InlineData(10, "10s ago")]
    [InlineData(59, "59s ago")]
    [InlineData(60, "1m ago")]
    [InlineData(3599, "59m ago")]
    [InlineData(3600, "1h ago")]
    [InlineData(86399, "23h ago")]
    [InlineData(86400, "1d ago")]
    public void HumanizeAge_ShouldSwitchUnitsAtEachBoundary(double seconds, string expected)
    {
        Assert.Equal(expected, ClientStatusDisplay.HumanizeAge(seconds));
    }

    [Theory]
    [InlineData("https://rmpls.inspired.codes/", "rmpls.inspired.codes")]
    [InlineData("https://psrun.inspired.codes", "psrun.inspired.codes")]
    [InlineData("https://psrun.inspired.codes/app/", "psrun.inspired.codes")]
    [InlineData("http://localhost:54971/", "localhost:54971")]
    [InlineData("https://hub.example.test:443/", "hub.example.test")]
    [InlineData("https://hub.example.test:8443/", "hub.example.test:8443")]
    [InlineData("", "")]
    [InlineData(null, "")]
    [InlineData("not a url", "")]
    [InlineData("/relative/path", "")]
    public void HubHost_ShowsHostAndOnlyANonDefaultPort(string? serverUrl, string expected)
    {
        Assert.Equal(expected, ClientStatusDisplay.HubHost(serverUrl));
    }

    [Fact]
    public void HubDot_FollowsTheActiveClientsHub_EvenWhenAnotherHubIsReachable()
    {
        // Clients on two Hubs: one answered (aggregate true), but not the active client's.
        var activeStatus = new ClientStatus { HubUnreachable = true };

        Assert.Equal("offline", ClientStatusDisplay.HubDot(deviceOnline: true, hubReachable: true, hasWatchdogResult: true, activeStatus));
    }

    [Fact]
    public void HubDot_ActiveClientsHubReached_IsOnline()
    {
        var activeStatus = new ClientStatus { Health = ClientHealth.Offline, HubUnreachable = false };

        // The Hub answered even though the Worker behind it is offline - the Hub node is green.
        Assert.Equal("online", ClientStatusDisplay.HubDot(deviceOnline: true, hubReachable: false, hasWatchdogResult: true, activeStatus));
    }

    [Theory]
    [InlineData(true, "online")]
    [InlineData(false, "offline")]
    [InlineData(null, "unknown")]
    public void HubDot_WithoutARecordedActiveStatus_FallsBackToTheAggregate(bool? hubReachable, string expected)
    {
        Assert.Equal(expected, ClientStatusDisplay.HubDot(deviceOnline: true, hubReachable, hasWatchdogResult: true, activeStatus: null));
    }

    [Fact]
    public void HubDot_BeforeTheFirstWatchdogResult_IgnoresTheActiveStatus()
    {
        var activeStatus = new ClientStatus { HubUnreachable = true };

        Assert.Equal("unknown", ClientStatusDisplay.HubDot(deviceOnline: true, hubReachable: null, hasWatchdogResult: false, activeStatus));
    }

    [Fact]
    public void HubDot_DeviceOffline_IsUnknown()
    {
        var activeStatus = new ClientStatus { HubUnreachable = false };

        Assert.Equal("unknown", ClientStatusDisplay.HubDot(deviceOnline: false, hubReachable: true, hasWatchdogResult: true, activeStatus));
    }

    [Fact]
    public void LastSeenShort_ShowsTheHubComputedAge()
    {
        var status = new ClientStatus { Health = ClientHealth.Degraded, MissedPolls = 2, LastSeenUtc = DateTime.UtcNow.AddSeconds(-35), SecondsSinceLastSeen = 35 };

        Assert.Equal("seen 35s ago", ClientStatusDisplay.LastSeenShort(status));
    }

    [Fact]
    public void LastSeenShort_RecentCheckIn_SaysJustNow()
    {
        var status = new ClientStatus { Health = ClientHealth.Online, LastSeenUtc = DateTime.UtcNow, SecondsSinceLastSeen = 3 };

        Assert.Equal("seen just now", ClientStatusDisplay.LastSeenShort(status));
    }

    [Fact]
    public void LastSeenShort_NeverCheckedIn_SaysNeverSeen()
    {
        var status = new ClientStatus { Health = ClientHealth.Offline, LastSeenUtc = null, SecondsSinceLastSeen = null };

        Assert.Equal("never seen", ClientStatusDisplay.LastSeenShort(status));
    }

    [Fact]
    public void LastSeenShort_HubUnreachableOrNoStatus_IsEmpty()
    {
        // An age we couldn't refresh would be stale; the chain caption explains instead.
        var unreachable = new ClientStatus { HubUnreachable = true, LastSeenUtc = DateTime.UtcNow, SecondsSinceLastSeen = 5 };

        Assert.Equal(string.Empty, ClientStatusDisplay.LastSeenShort(unreachable));
        Assert.Equal(string.Empty, ClientStatusDisplay.LastSeenShort(null));
    }

    [Theory]
    [InlineData(ClientHealth.Online, null, "")]
    [InlineData(ClientHealth.Degraded, 1, "The Worker missed 1 check-in.")]
    [InlineData(ClientHealth.Degraded, 3, "The Worker missed 3 check-ins.")]
    [InlineData(ClientHealth.Degraded, null, "The Worker is missing check-ins.")]
    [InlineData(ClientHealth.Offline, null, "The Worker is offline.")]
    public void WorkerCaption_NamesTheMissedCountWhenKnown(ClientHealth health, int? missedPolls, string expected)
    {
        var status = new ClientStatus { Health = health, MissedPolls = missedPolls };

        Assert.Equal(expected, ClientStatusDisplay.WorkerCaption(status));
    }
}
