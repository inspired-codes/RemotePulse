using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Microsoft.JSInterop;

namespace InspiredCodes.RemotePulse.App.Services;

/// <summary>
/// Keeps <see cref="AppState.ClientStatuses"/> fresh by polling the Hub's
/// <c>GET /api/clients/status</c> watchdog endpoint, so the UI can show whether each paired
/// machine is actually reachable rather than just whether a pairing record exists locally.
/// </summary>
public class ClientWatchdog : IDisposable
{
    /// <summary>
    /// How often we ask the Hub. Kept close to the Worker's own 12s cadence on purpose: the
    /// Degraded grade only spans a couple of missed check-ins, so polling much slower than the
    /// Worker would routinely skip straight from green to red and the amber warning would never
    /// be seen. Still cheap - one small JSON response covering every paired machine.
    /// </summary>
    private static readonly TimeSpan CheckInterval = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Health arrives as a string ("Online"), matching the Hub's global string-enum policy - the
    /// default web options would try to read it as a number and fail.
    /// </summary>
    private static readonly JsonSerializerOptions StatusJsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _http;
    private readonly AppState _appState;
    private readonly CryptoService _crypto;
    private readonly IJSRuntime? _js;

    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private DotNetObjectReference<ClientWatchdog>? _selfRef;

    /// <summary>
    /// Whether the app is currently backgrounded. Polling is suspended while it is: on a phone
    /// this loop would otherwise keep waking the radio every few seconds for a screen nobody is
    /// looking at.
    /// </summary>
    private volatile bool _isHidden;

    /// <summary>
    /// Whether the browser reports itself offline (<c>navigator.onLine === false</c>). Polling is
    /// skipped while it is - a fetch to the Hub can hang for many seconds on a phone with no
    /// connectivity before it fails.
    /// </summary>
    private volatile bool _isOffline;

    /// <param name="js">
    /// Optional so tests can construct the watchdog without a browser; when absent the loop
    /// simply never suspends.
    /// </param>
    public ClientWatchdog(HttpClient http, AppState appState, CryptoService crypto, IJSRuntime? js = null)
    {
        _http = http;
        _appState = appState;
        _crypto = crypto;
        _js = js;
    }

    public void Start()
    {
        if (_loopTask != null)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _loopTask = RunLoopAsync(_cts.Token);
        _ = RegisterBrowserHooksAsync();
    }

    public void Stop()
    {
        try
        {
            _cts?.Cancel();
        }
        catch
        {
            // Nothing useful to do if cancellation itself throws during teardown.
        }
        _cts?.Dispose();
        _cts = null;
        _loopTask = null;

        if (_js != null)
        {
            _ = _js.InvokeVoidAsync("qrScannerInterop.unregisterVisibilityCallback");
            _ = _js.InvokeVoidAsync("qrScannerInterop.unregisterConnectivityCallback");
        }
        _selfRef?.Dispose();
        _selfRef = null;
    }

    private async Task RegisterBrowserHooksAsync()
    {
        if (_js == null)
        {
            return;
        }

        try
        {
            _selfRef = DotNetObjectReference.Create(this);
            await _js.InvokeVoidAsync("qrScannerInterop.registerVisibilityCallback", _selfRef).ConfigureAwait(false);
            await _js.InvokeVoidAsync("qrScannerInterop.registerConnectivityCallback", _selfRef).ConfigureAwait(false);
            _isHidden = await _js.InvokeAsync<bool>("qrScannerInterop.isPageHidden").ConfigureAwait(false);
            _isOffline = !await _js.InvokeAsync<bool>("qrScannerInterop.isOnline").ConfigureAwait(false);
            _appState.DeviceOnline = !_isOffline;
        }
        catch
        {
            // Without the hooks the watchdog just keeps polling - degraded, not broken.
        }
    }

    /// <summary>
    /// Called from JS when the app is backgrounded or brought back. Returning to the foreground
    /// triggers an immediate check so the dots are current the moment the user looks at them,
    /// rather than showing a stale snapshot until the next tick.
    /// </summary>
    [JSInvokable]
    public async Task OnVisibilityChanged(bool hidden)
    {
        _isHidden = hidden;

        if (!hidden)
        {
            await CheckAllAsync(_cts?.Token ?? CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Called from JS on the browser's online/offline events. Coming back online triggers an
    /// immediate check so the App -> Hub -> Worker chain refreshes at once rather than after a
    /// full tick.
    /// </summary>
    [JSInvokable]
    public async Task OnConnectivityChanged(bool online)
    {
        _isOffline = !online;
        _appState.DeviceOnline = online;
        _appState.NotifyStateChanged();

        if (online)
        {
            await CheckAllAsync(_cts?.Token ?? CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        // Check immediately on start so the badge doesn't sit blank for a full interval.
        await CheckAllAsync(cancellationToken).ConfigureAwait(false);

        using PeriodicTimer timer = new PeriodicTimer(CheckInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                // Skip the network entirely while backgrounded or offline. The timer tick itself
                // is cheap; the HTTP request is what costs radio power and data - and offline it
                // just hangs until it times out.
                if (_isHidden || _isOffline)
                {
                    continue;
                }

                await CheckAllAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal teardown when the page is disposed.
        }
    }

    /// <summary>
    /// Refreshes liveness for every paired machine. Paired clients are grouped by ServerUrl and
    /// queried one batch request per distinct Hub - normally exactly one request total, and a
    /// multi-Hub setup stays correct for free since each Hub only knows its own machines.
    /// </summary>
    public async Task CheckAllAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_appState.AppId) || _appState.PairedClients.Count == 0)
        {
            return;
        }

        bool changed = false;
        bool anyHubReached = false;

        foreach (var hubGroup in _appState.PairedClients.GroupBy(c => c.ServerUrl.TrimEnd('/')))
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            string serverUrl = hubGroup.Key;
            List<ClientStatus>? statuses = await TryFetchStatusesAsync(serverUrl, cancellationToken).ConfigureAwait(false);

            if (statuses == null)
            {
                // Couldn't reach this Hub - mark its machines unknown rather than offline. We
                // genuinely don't know their state, and blaming the client PC for the phone's
                // connectivity would send the operator chasing the wrong problem.
                foreach (var client in hubGroup)
                {
                    changed |= ApplyStatus(new ClientStatus
                    {
                        MachineId = client.MachineId,
                        HubUnreachable = true
                    });
                }
                continue;
            }

            anyHubReached = true;

            foreach (var status in statuses)
            {
                changed |= ApplyStatus(status);
            }

            // A machine the Hub didn't mention isn't registered there (or the pairing was
            // dropped server-side); leaving a stale "online" for it would be a lie.
            var reported = statuses.Select(s => s.MachineId).ToHashSet();
            foreach (var client in hubGroup.Where(c => !reported.Contains(c.MachineId)))
            {
                changed |= ApplyStatus(new ClientStatus
                {
                    MachineId = client.MachineId,
                    Health = ClientHealth.Offline
                });
            }
        }

        if (_appState.HubReachable != anyHubReached)
        {
            // First result (was null): set it silently - ApplyStatus already logs per-machine.
            if (_appState.HubReachable == true && !anyHubReached)
            {
                _appState.Log("Watchdog: lost contact with the Hub.");
            }
            else if (_appState.HubReachable == false && anyHubReached)
            {
                _appState.Log("Watchdog: Hub reachable again.");
            }
            _appState.HubReachable = anyHubReached;
            changed = true;
        }

        if (!_appState.HasWatchdogResult)
        {
            _appState.HasWatchdogResult = true;
            changed = true;
        }

        if (changed)
        {
            _appState.NotifyStateChanged();
        }
    }

    private async Task<List<ClientStatus>?> TryFetchStatusesAsync(string serverUrl, CancellationToken cancellationToken)
    {
        try
        {
            string timestamp = DateTime.UtcNow.ToString("o");
            string nonce = Guid.NewGuid().ToString("N");
            string signature = await _crypto.SignHeaderMessageAsync("GET", "/api/clients/status", _appState.AppId, timestamp, nonce).ConfigureAwait(false);

            using var request = new HttpRequestMessage(HttpMethod.Get, $"{serverUrl}/api/clients/status");
            request.Headers.Add("X-App-Id", _appState.AppId);
            request.Headers.Add("X-Timestamp", timestamp);
            request.Headers.Add("X-Nonce", nonce);
            request.Headers.Add("X-Signature", signature);
            request.Headers.Add(ProtocolConstants.VersionHeaderName, ProtocolConstants.CurrentVersion);

            using var response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            return await response.Content
                .ReadFromJsonAsync<List<ClientStatus>>(StatusJsonOptions, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            // Network failure, Hub down, signing failure - all mean "we don't know".
            return null;
        }
    }

    /// <summary>
    /// Stores a status and reports whether anything user-visible changed. Transitions are logged
    /// to the console panel; steady state is not, or a 20s poll would flood the 200-line log.
    /// </summary>
    private bool ApplyStatus(ClientStatus status)
    {
        _appState.ClientStatuses.TryGetValue(status.MachineId, out var previous);
        _appState.ClientStatuses[status.MachineId] = status;

        if (previous == null)
        {
            return true;
        }

        bool stateChanged = previous.Health != status.Health
            || previous.HubUnreachable != status.HubUnreachable;

        // A new version between two real Hub reports is how a remote "Update Worker" shows it
        // landed. Statuses we synthesize (Hub unreachable) carry no version, so they don't count.
        bool versionChanged = previous.WorkerVersion != status.WorkerVersion;
        if (versionChanged && status.WorkerVersion != null && !previous.HubUnreachable && !status.HubUnreachable)
        {
            string Updated(string name) => $"Watchdog: {name} now runs Worker {status.WorkerVersion}.";
            _appState.Log(Updated(DescribeMachine(status.MachineId)), Updated(AppState.UploadMachineName(status.MachineId)));
        }

        if (stateChanged)
        {
            // The console names the machine by its alias; the uploaded log must not (see AppState.Log).
            string Describe(string name) => status.HubUnreachable
                ? $"Watchdog: lost contact with the Hub - availability of {name} is unknown."
                : status.Health switch
                {
                    ClientHealth.Online => $"Watchdog: {name} is online.",
                    ClientHealth.Degraded => $"Watchdog: {name} missed {status.MissedPolls} check-in(s) - may be unstable.",
                    _ => $"Watchdog: {name} is offline."
                };
            _appState.Log(Describe(DescribeMachine(status.MachineId)), Describe(AppState.UploadMachineName(status.MachineId)));
        }

        return stateChanged || versionChanged;
    }

    private string DescribeMachine(string machineId)
    {
        var client = _appState.PairedClients.FirstOrDefault(c => c.MachineId == machineId);
        return client != null && !string.IsNullOrEmpty(client.Alias) ? client.Alias : machineId;
    }

    public void Dispose() => Stop();
}
