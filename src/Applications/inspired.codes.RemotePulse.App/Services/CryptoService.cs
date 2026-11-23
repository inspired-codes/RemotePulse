using Microsoft.JSInterop;

namespace InspiredCodes.RemotePulse.App.Services;

public class CryptoService
{
    private readonly IJSRuntime _js;
    private string? _publicKeyBase64;

    protected CryptoService()
    {
        _js = null!;
    }

    public CryptoService(IJSRuntime js)
    {
        _js = js ?? throw new ArgumentNullException(nameof(js));
    }

    public virtual async Task<string> GenerateAppKeysAsync()
    {
        var result = await _js.InvokeAsync<AppKeysResult>("qrScannerInterop.generateAppKeys");
        _publicKeyBase64 = result.PublicKeyBase64;
        return result.PublicKeyBase64;
    }

    /// <summary>
    /// Verifies the private key is actually present in IndexedDB - localStorage and IndexedDB
    /// are separate stores that can end up out of sync, so a cached App ID/public key in
    /// localStorage is not proof the matching private key still exists.
    /// </summary>
    public virtual async Task<bool> HasPrivateKeyAsync()
    {
        return await _js.InvokeAsync<bool>("qrScannerInterop.hasPrivateKey");
    }

    public virtual async Task<string> SignHeaderMessageAsync(string method, string path, string appId, string timestamp, string nonce)
    {
        string message = $"{method.ToUpperInvariant()}:{path}:{appId}:{timestamp}:{nonce}";
        // The private key is now loaded securely from IndexedDB within JS
        return await _js.InvokeAsync<string>("qrScannerInterop.signMessage", "", message);
    }

    /// <summary>
    /// Signs an arbitrary payload string with the App's ECDSA private key - the co-presence
    /// secret (SEC-6 proof-of-possession) and the command envelope (SEC-1/SEC-4 anti-replay
    /// binding) both go through this, hence the generic name.
    /// </summary>
    public virtual async Task<string> SignBoundPayloadAsync(string payload)
    {
        return await _js.InvokeAsync<string>("qrScannerInterop.signMessage", "", payload);
    }

    public virtual async Task<string> HybridEncryptPayloadAsync(string jsonPayload, string recipientPublicKeyBase64)
    {
        return await _js.InvokeAsync<string>("qrScannerInterop.hybridEncryptPayload", jsonPayload, recipientPublicKeyBase64);
    }

    public virtual async Task<string> GenerateReplyKeyAsync(string commandId, string machineId, int? timeoutSeconds)
    {
        return await _js.InvokeAsync<string>("qrScannerInterop.generateReplyKey", commandId, machineId, timeoutSeconds ?? 90);
    }

    public virtual async Task<string> DecryptResultAsync(string commandId, string encryptedBlobBase64)
    {
        return await _js.InvokeAsync<string>("qrScannerInterop.decryptResult", commandId, encryptedBlobBase64);
    }

    public virtual async Task<List<PendingCommandRecord>> GetPendingCommandsAsync()
    {
        return await _js.InvokeAsync<List<PendingCommandRecord>>("qrScannerInterop.getPendingCommands");
    }

    public virtual async Task RemovePendingCommandAsync(string commandId)
    {
        await _js.InvokeVoidAsync("qrScannerInterop.removePendingCommand", commandId);
    }

    public class AppKeysResult
    {
        public string PublicKeyBase64 { get; set; } = string.Empty;
    }

    public class PendingCommandRecord
    {
        public string CommandId { get; set; } = string.Empty;
        public string MachineId { get; set; } = string.Empty;
        public string SentAtUtc { get; set; } = string.Empty;
        public int TimeoutSeconds { get; set; } = 90;
    }
}
