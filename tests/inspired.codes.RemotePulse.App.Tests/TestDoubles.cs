using Microsoft.JSInterop;
using InspiredCodes.RemotePulse.App.Services;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// Stands in for the browser. The App's crypto and storage both go through JS interop, so faking
/// <see cref="IJSRuntime"/> is what makes the surrounding C# testable without a browser or bUnit.
/// </summary>
public sealed class FakeJSRuntime : IJSRuntime
{
    private readonly Dictionary<string, object?> _responses = new();
    private readonly Dictionary<string, string> _localStorage = new();

    /// <summary>Every interop call made, in order - lets tests assert on what was invoked.</summary>
    public List<string> Calls { get; } = new();

    public FakeJSRuntime()
    {
        // Enough for the paths under test: a canned signature and a present private key.
        _responses["qrScannerInterop.signMessage"] = Convert.ToBase64String(new byte[64]);
        _responses["qrScannerInterop.hasPrivateKey"] = true;
        _responses["qrScannerInterop.generateAppKeys"] = new CryptoService.AppKeysResult { PublicKeyBase64 = "fake-public-key" };
    }

    public void Setup(string identifier, object? result) => _responses[identifier] = result;

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
    {
        Calls.Add(identifier);

        if (identifier == "localStorage.getItem" && args?.Length > 0 && args[0] is string getKey)
        {
            if (_localStorage.TryGetValue(getKey, out string? val))
            {
                return ValueTask.FromResult((TValue)(object)val);
            }
            return ValueTask.FromResult(default(TValue)!);
        }

        if (identifier == "localStorage.setItem" && args?.Length >= 2 && args[0] is string setKey && args[1] is string setVal)
        {
            _localStorage[setKey] = setVal;
            return ValueTask.FromResult(default(TValue)!);
        }

        if (identifier == "localStorage.removeItem" && args?.Length > 0 && args[0] is string removeKey)
        {
            _localStorage.Remove(removeKey);
            return ValueTask.FromResult(default(TValue)!);
        }

        if (_responses.TryGetValue(identifier, out object? value) && value is TValue typed)
        {
            return ValueTask.FromResult(typed);
        }

        return ValueTask.FromResult(default(TValue)!);
    }

    public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        => InvokeAsync<TValue>(identifier, args);
}

/// <summary>Routes HttpClient traffic to a delegate so tests can script the Hub's responses.</summary>
public sealed class MockHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler) : HttpMessageHandler
{
    public int RequestCount { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestCount++;
        return await handler(request);
    }
}
