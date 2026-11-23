using System.Net;
using System.Net.Http.Json;
using InspiredCodes.RemotePulse.App.Models;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// The watchdog's decision-making: what it asks the Hub, and how it interprets silence.
/// </summary>
public class ClientWatchdogTests
{
    private const string HubUrl = "https://hub.example.test";

    [Fact]
    public async Task CheckAll_ShouldRecordLivenessReportedByTheHub()
    {
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = DateTime.UtcNow, secondsSinceLastSeen = 4.0, health = "Online", missedPolls = 0 },
        }));

        await sut.Watchdog.CheckAllAsync();

        var status = sut.State.GetClientStatus("PC-1");
        Assert.Equal(ClientHealth.Online, status.Health);
        Assert.False(status.HubUnreachable);
        Assert.Equal(4.0, status.SecondsSinceLastSeen);
        Assert.True(sut.State.HasWatchdogResult);
    }

    [Fact]
    public async Task CheckAll_ShouldSignItsRequestAndTargetTheStatusEndpoint()
    {
        HttpRequestMessage? captured = null;
        var sut = Build(request =>
        {
            captured = request;
            return Json(HttpStatusCode.OK, Array.Empty<object>());
        });

        await sut.Watchdog.CheckAllAsync();

        Assert.NotNull(captured);
        Assert.Equal($"{HubUrl}/api/clients/status", captured.RequestUri!.ToString());
        Assert.True(captured.Headers.Contains("X-App-Id"));
        Assert.True(captured.Headers.Contains("X-Timestamp"));
        Assert.True(captured.Headers.Contains("X-Nonce"));
        Assert.True(captured.Headers.Contains("X-Signature"));
    }

    [Fact]
    public async Task WhenTheHubIsUnreachable_ShouldReportUnknownRatherThanOffline()
    {
        var sut = Build(_ => throw new HttpRequestException("network down"));

        await sut.Watchdog.CheckAllAsync();

        // The crucial distinction: we don't know, so we must not claim the client is dead.
        var status = sut.State.GetClientStatus("PC-1");
        Assert.True(status.HubUnreachable);
        Assert.Equal(ClientHealth.Offline, status.Health);
    }

    [Fact]
    public async Task WhenTheHubReturnsAnError_ShouldAlsoBeTreatedAsUnknown()
    {
        var sut = Build(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)));

        await sut.Watchdog.CheckAllAsync();

        Assert.True(sut.State.GetClientStatus("PC-1").HubUnreachable);
    }

    [Fact]
    public async Task AMachineTheHubDoesntMentionShouldNotKeepAStaleOnlineState()
    {
        var responses = new Queue<Func<Task<HttpResponseMessage>>>();
        responses.Enqueue(() => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)3.0, health = "Online", missedPolls = (int?)0 },
        }));
        // Second cycle: the Hub no longer knows about PC-1 (pairing dropped server-side).
        responses.Enqueue(() => Json(HttpStatusCode.OK, Array.Empty<object>()));

        var sut = Build(_ => responses.Dequeue()());

        await sut.Watchdog.CheckAllAsync();
        Assert.Equal(ClientHealth.Online, sut.State.GetClientStatus("PC-1").Health);

        await sut.Watchdog.CheckAllAsync();
        Assert.Equal(ClientHealth.Offline, sut.State.GetClientStatus("PC-1").Health);
    }

    [Fact]
    public async Task WithNoPairedClients_ShouldNotCallTheHubAtAll()
    {
        var sut = Build(_ => Json(HttpStatusCode.OK, Array.Empty<object>()), withPairedClient: false);

        await sut.Watchdog.CheckAllAsync();

        Assert.Equal(0, sut.Handler.RequestCount);
    }

    [Fact]
    public async Task ShouldQueryEachDistinctHubOnce_NotEachClient()
    {
        var sut = Build(_ => Json(HttpStatusCode.OK, Array.Empty<object>()), withPairedClient: false);
        // Three machines, two Hubs: batching by Hub means two requests, not three.
        sut.State.PairedClients.Add(new PairedClient { MachineId = "PC-1", ServerUrl = HubUrl });
        sut.State.PairedClients.Add(new PairedClient { MachineId = "PC-2", ServerUrl = HubUrl });
        sut.State.PairedClients.Add(new PairedClient { MachineId = "PC-3", ServerUrl = "https://other.example.test" });

        await sut.Watchdog.CheckAllAsync();

        Assert.Equal(2, sut.Handler.RequestCount);
    }

    [Fact]
    public async Task GoingOffline_ShouldBeLoggedOnceAsATransitionNotEveryCycle()
    {
        string health = "Online";
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)5.0, health = health, missedPolls = (int?)0 },
        }));

        await sut.Watchdog.CheckAllAsync();
        health = "Offline";
        await sut.Watchdog.CheckAllAsync();

        Assert.Equal(1, CountOccurrences(sut.State.ConsoleOutput, "is offline"));

        // Steady state must stay quiet, or a 10s poll would flood the capped console log.
        await sut.Watchdog.CheckAllAsync();
        await sut.Watchdog.CheckAllAsync();
        Assert.Equal(1, CountOccurrences(sut.State.ConsoleOutput, "is offline"));
    }

    [Fact]
    public async Task StateChangeLog_NamesTheAliasOnDevice_ButNotInTheUploadedLog()
    {
        string health = "Online";
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)5.0, health = health, missedPolls = (int?)0 },
        }));
        sut.State.PairedClients[0].Alias = "Reception PC";

        await sut.Watchdog.CheckAllAsync();
        health = "Offline";
        await sut.Watchdog.CheckAllAsync();

        Assert.Contains("Watchdog: Reception PC is offline.", sut.State.ConsoleOutput);
        Assert.Contains("Watchdog: machine PC-1 is offline.", sut.State.DiagnosticOutput);
        Assert.DoesNotContain("Reception", sut.State.DiagnosticOutput);
    }

    [Fact]
    public async Task ANewWorkerVersion_ShouldBeLoggedOnce_SoARemoteUpdateIsVisible()
    {
        // A 1.1.x Worker reports no version; after "Update Worker" the restarted 1.2.0 does.
        string? version = null;
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)5.0, health = "Online", missedPolls = (int?)0, workerVersion = version },
        }));
        sut.State.PairedClients[0].Alias = "Reception PC";

        await sut.Watchdog.CheckAllAsync();
        version = "1.2.0";
        await sut.Watchdog.CheckAllAsync();
        await sut.Watchdog.CheckAllAsync();

        Assert.Equal("1.2.0", sut.State.GetClientStatus("PC-1").WorkerVersion);
        Assert.Equal(1, CountOccurrences(sut.State.ConsoleOutput, "Watchdog: Reception PC now runs Worker 1.2.0."));
        Assert.Contains("Watchdog: machine PC-1 now runs Worker 1.2.0.", sut.State.DiagnosticOutput);
        Assert.DoesNotContain("Reception", sut.State.DiagnosticOutput);
    }

    [Fact]
    public async Task ALostAndRegainedHub_ShouldNotBeReportedAsAWorkerUpdate()
    {
        bool hubUp = true;
        var sut = Build(_ => hubUp
            ? Json(HttpStatusCode.OK, new[]
            {
                new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)5.0, health = "Online", missedPolls = (int?)0, workerVersion = "1.2.0" },
            })
            : throw new HttpRequestException("network down"));

        await sut.Watchdog.CheckAllAsync();
        hubUp = false;
        await sut.Watchdog.CheckAllAsync();
        hubUp = true;
        await sut.Watchdog.CheckAllAsync();

        Assert.DoesNotContain("now runs Worker", sut.State.ConsoleOutput);
    }

    [Fact]
    public async Task ReturningToTheForeground_ShouldRefreshImmediately()
    {
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)2.0, health = "Online", missedPolls = (int?)0 },
        }));

        // Backgrounding costs nothing to assert here; what matters is that coming back does not
        // leave the user staring at a stale snapshot until the next 10s tick.
        await sut.Watchdog.OnVisibilityChanged(hidden: true);
        int afterHidden = sut.Handler.RequestCount;

        await sut.Watchdog.OnVisibilityChanged(hidden: false);

        Assert.Equal(afterHidden + 1, sut.Handler.RequestCount);
        Assert.Equal(ClientHealth.Online, sut.State.GetClientStatus("PC-1").Health);
    }

    [Fact]
    public async Task PassingThroughDegraded_ShouldBeLoggedAsItsOwnTransition()
    {
        string health = "Online";
        int missed = 0;
        var sut = Build(_ => Json(HttpStatusCode.OK, new[]
        {
            new { machineId = "PC-1", lastSeenUtc = (DateTime?)DateTime.UtcNow, secondsSinceLastSeen = (double?)20.0, health = health, missedPolls = (int?)missed },
        }));

        await sut.Watchdog.CheckAllAsync();

        health = "Degraded";
        missed = 2;
        await sut.Watchdog.CheckAllAsync();

        // Amber is a distinct, reportable event - not silently folded into "still not offline".
        Assert.Equal(ClientHealth.Degraded, sut.State.GetClientStatus("PC-1").Health);
        Assert.Equal(1, CountOccurrences(sut.State.ConsoleOutput, "missed 2 check-in(s)"));
        Assert.Equal(0, CountOccurrences(sut.State.ConsoleOutput, "is offline"));

        health = "Offline";
        missed = 9;
        await sut.Watchdog.CheckAllAsync();
        Assert.Equal(1, CountOccurrences(sut.State.ConsoleOutput, "is offline"));
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        int count = 0;
        int index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }
        return count;
    }

    private static Task<HttpResponseMessage> Json(HttpStatusCode status, object payload)
        => Task.FromResult(new HttpResponseMessage(status) { Content = JsonContent.Create(payload) });

    private static Harness Build(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond, bool withPairedClient = true)
    {
        var js = new FakeJSRuntime();
        var state = new AppState(new LocalStorageService(js), new CryptoService(js))
        {
            AppId = Guid.NewGuid().ToString()
        };

        if (withPairedClient)
        {
            state.PairedClients.Add(new PairedClient { MachineId = "PC-1", ServerUrl = HubUrl });
        }

        var handler = new MockHttpMessageHandler(respond);
        var watchdog = new ClientWatchdog(new HttpClient(handler), state, new CryptoService(js));

        return new Harness(watchdog, state, handler);
    }

    private sealed record Harness(ClientWatchdog Watchdog, AppState State, MockHttpMessageHandler Handler);
}
