using System;
using System.Net.Http;
using System.Text;

namespace InspiredCodes.RemotePulse.Shared.Cryptography;

/// <summary>
/// Canonical implementation of HTTP request signing and message construction (SEC-9).
/// Single source of truth across Worker, Hub, and integration tests.
/// </summary>
public static class RequestSigner
{
    /// <summary>
    /// Constructs the canonical message string to sign: "{METHOD}:{path}:{clientId}:{timestamp}:{nonce}".
    /// </summary>
    public static string CreateSignatureMessage(string method, string path, string clientId, string timestamp, string nonce)
    {
        string normalizedMethod = method?.ToUpperInvariant() ?? string.Empty;
        string normalizedPath = NormalizePath(path);
        return $"{normalizedMethod}:{normalizedPath}:{clientId}:{timestamp}:{nonce}";
    }

    /// <summary>
    /// Normalizes a request path ensuring a leading slash and stripping any query string.
    /// </summary>
    public static string NormalizePath(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return "/";
        }

        string raw = path;
        int q = raw.IndexOf('?');
        string clean = q >= 0 ? raw.Substring(0, q) : raw;
        return clean.StartsWith('/') ? clean : "/" + clean;
    }

    /// <summary>
    /// Extracts the canonical path from an <see cref="HttpRequestMessage"/>.
    /// </summary>
    public static string ExtractPath(HttpRequestMessage request)
    {
        if (request.RequestUri == null)
        {
            return "/";
        }

        if (request.RequestUri.IsAbsoluteUri)
        {
            return request.RequestUri.AbsolutePath;
        }

        return NormalizePath(request.RequestUri.OriginalString);
    }

    /// <summary>
    /// Signs an outgoing HTTP request and appends the SEC-9 authentication headers:
    /// X-Client-Id, X-Timestamp, X-Nonce, and X-Signature.
    /// </summary>
    public static void AddSignatureHeaders(HttpRequestMessage request, IKeyPairManager keyManager, string clientId)
    {
        string nonce = Guid.NewGuid().ToString("N");
        string timestamp = DateTimeOffset.UtcNow.ToString("o");

        string method = request.Method.Method.ToUpperInvariant();
        string path = ExtractPath(request);

        string messageToSign = CreateSignatureMessage(method, path, clientId, timestamp, nonce);
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageToSign);

        byte[] signatureBytes = keyManager.SignData(messageBytes);
        string signatureBase64 = Convert.ToBase64String(signatureBytes);

        request.Headers.Remove("X-Client-Id");
        request.Headers.Remove("X-Timestamp");
        request.Headers.Remove("X-Nonce");
        request.Headers.Remove("X-Signature");

        request.Headers.Add("X-Client-Id", clientId);
        request.Headers.Add("X-Timestamp", timestamp);
        request.Headers.Add("X-Nonce", nonce);
        request.Headers.Add("X-Signature", signatureBase64);
    }
}
