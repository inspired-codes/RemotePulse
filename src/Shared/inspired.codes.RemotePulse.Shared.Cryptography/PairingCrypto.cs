using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace InspiredCodes.RemotePulse.Shared.Cryptography;

/// <summary>
/// Pure-C# cryptographic primitives for Pairing v2 key binding (see
/// <c>docs/specs/pairing-v2-key-binding-spec.md</c> §4.1).
/// <para>
/// Uses only <see cref="SHA256"/>, <see cref="HMACSHA256"/>, and <see cref="HKDF"/>, which have
/// managed implementations on <c>browser-wasm</c> and carry no
/// <c>[UnsupportedOSPlatform("browser")]</c> restriction in .NET 10. This allows the Worker,
/// Hub, Blazor WebAssembly App, and xUnit tests to share the exact same implementation.
/// </para>
/// </summary>
public static class PairingCrypto
{
    /// <summary>Length in characters of an unpadded base64url-encoded 256-bit (32-byte) value.</summary>
    public const int Base64Url256Length = 43;

    private static readonly byte[] PairingIdHkdfInfo = Encoding.UTF8.GetBytes("RemotePulse/pairing/v2/id");
    private static readonly byte[] BindKeyHkdfInfo = Encoding.UTF8.GetBytes("RemotePulse/pairing/v2/bind");

    private const string AppBindDomainPrefix = "RemotePulse/pairing/v2/app-bind:";
    private const string SasDomainPrefix = "RemotePulse/pairing/v2/sas:";

    /// <summary>
    /// Generates a fresh 256-bit CSPRNG secret encoded as 43 unpadded base64url characters.
    /// </summary>
    public static string GenerateSecret()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        try
        {
            return ToBase64Url(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Derives the public match key <c>pid</c> from the QR secret <paramref name="secret"/>:
    /// <c>B64U(HKDF-SHA256(ikm = UTF8(S), salt = empty, info = "RemotePulse/pairing/v2/id", L = 32))</c>.
    /// </summary>
    public static string DerivePairingId(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        byte[] ikm = Encoding.UTF8.GetBytes(secret);
        byte[] derived = new byte[32];
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, derived, salt: ReadOnlySpan<byte>.Empty, info: PairingIdHkdfInfo);
            return ToBase64Url(derived);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
            CryptographicOperations.ZeroMemory(derived);
        }
    }

    /// <summary>
    /// Derives the 256-bit HMAC key <c>bindKey</c> from the QR secret <paramref name="secret"/>:
    /// <c>HKDF-SHA256(ikm = UTF8(S), salt = empty, info = "RemotePulse/pairing/v2/bind", L = 32)</c>.
    /// Callers should zero the returned array with <see cref="CryptographicOperations.ZeroMemory"/> when done.
    /// </summary>
    public static byte[] DeriveBindKey(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        byte[] ikm = Encoding.UTF8.GetBytes(secret);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, outputLength: 32, salt: Array.Empty<byte>(), info: BindKeyHkdfInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>
    /// Computes the Worker public-key fingerprint <c>fp</c> over the DER-encoded SubjectPublicKeyInfo bytes:
    /// <c>B64U(SHA-256(WorkerSPKI))</c>.
    /// </summary>
    public static string ComputePublicKeyFingerprint(string publicKeySpkiBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(publicKeySpkiBase64);
        byte[] spkiDer = Convert.FromBase64String(publicKeySpkiBase64);
        return ComputePublicKeyFingerprint(spkiDer);
    }

    /// <summary>
    /// Computes the public-key fingerprint <c>fp</c> over raw DER-encoded SubjectPublicKeyInfo bytes:
    /// <c>B64U(SHA-256(WorkerSPKI))</c>.
    /// </summary>
    public static string ComputePublicKeyFingerprint(ReadOnlySpan<byte> spkiDerBytes)
    {
        if (spkiDerBytes.IsEmpty)
        {
            throw new ArgumentException("SPKI DER bytes must not be empty.", nameof(spkiDerBytes));
        }

        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(spkiDerBytes, hash);
        return ToBase64Url(hash);
    }

    /// <summary>
    /// Verifies in constant time whether <paramref name="publicKeySpkiBase64"/> matches the
    /// expected base64url SHA-256 fingerprint <paramref name="expectedFingerprint"/> from the QR link.
    /// </summary>
    public static bool VerifyPublicKeyFingerprint(string? publicKeySpkiBase64, string? expectedFingerprint)
    {
        if (string.IsNullOrWhiteSpace(publicKeySpkiBase64) || !IsValidBase64Url256(expectedFingerprint))
        {
            return false;
        }

        byte[] spkiDer;
        try
        {
            spkiDer = Convert.FromBase64String(publicKeySpkiBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        if (spkiDer.Length == 0)
        {
            return false;
        }

        string actualFingerprint = ComputePublicKeyFingerprint(spkiDer);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actualFingerprint),
            Encoding.ASCII.GetBytes(expectedFingerprint));
    }

    /// <summary>
    /// Computes the App-to-Worker key-binding tag <c>AppBindTag</c>:
    /// <c>B64U(HMAC-SHA256(bindKey, UTF8("RemotePulse/pairing/v2/app-bind:" + pid + ":" + fp + ":" + AppId + ":" + AppPublicKey)))</c>.
    /// </summary>
    public static string ComputeAppBindTag(
        string secret,
        string pairingId,
        string workerFingerprint,
        string appId,
        string appPublicKeyBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        ArgumentException.ThrowIfNullOrWhiteSpace(pairingId);
        ArgumentException.ThrowIfNullOrWhiteSpace(workerFingerprint);
        ArgumentException.ThrowIfNullOrWhiteSpace(appId);
        ArgumentException.ThrowIfNullOrWhiteSpace(appPublicKeyBase64);

        byte[] bindKey = DeriveBindKey(secret);
        try
        {
            string message = $"{AppBindDomainPrefix}{pairingId}:{workerFingerprint}:{appId}:{appPublicKeyBase64}";
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            Span<byte> mac = stackalloc byte[32];
            HMACSHA256.HashData(bindKey, messageBytes, mac);
            return ToBase64Url(mac);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bindKey);
        }
    }

    /// <summary>
    /// Verifies <paramref name="candidateTag"/> in constant time using <see cref="CryptographicOperations.FixedTimeEquals"/>.
    /// </summary>
    public static bool VerifyAppBindTag(
        string? secret,
        string? pairingId,
        string? workerFingerprint,
        string? appId,
        string? appPublicKeyBase64,
        string? candidateTag)
    {
        if (string.IsNullOrWhiteSpace(secret) ||
            string.IsNullOrWhiteSpace(pairingId) ||
            string.IsNullOrWhiteSpace(workerFingerprint) ||
            string.IsNullOrWhiteSpace(appId) ||
            string.IsNullOrWhiteSpace(appPublicKeyBase64) ||
            !IsValidBase64Url256(candidateTag))
        {
            return false;
        }

        string expectedTag = ComputeAppBindTag(secret, pairingId, workerFingerprint, appId, appPublicKeyBase64);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedTag),
            Encoding.ASCII.GetBytes(candidateTag));
    }

    /// <summary>
    /// Computes the 6-digit Short Authentication String (SAS) from both base64 SPKI public keys:
    /// first 4 bytes of <c>SHA-256(UTF8("RemotePulse/pairing/v2/sas:" + WorkerPublicKey + ":" + AppPublicKey))</c>
    /// interpreted as a big-endian <see cref="uint"/>, modulo 1,000,000, formatted as <c>123 456</c>.
    /// </summary>
    public static string ComputeSafetyCode(string workerPublicKeyBase64, string appPublicKeyBase64)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerPublicKeyBase64);
        ArgumentException.ThrowIfNullOrWhiteSpace(appPublicKeyBase64);

        string input = $"{SasDomainPrefix}{workerPublicKeyBase64}:{appPublicKeyBase64}";
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(inputBytes, hash);

        uint value = BinaryPrimitives.ReadUInt32BigEndian(hash[..4]) % 1_000_000u;
        uint high = value / 1_000u;
        uint low = value % 1_000u;
        return $"{high:D3} {low:D3}";
    }

    /// <summary>
    /// Returns true if <paramref name="value"/> is a 43-character unpadded base64url string.
    /// </summary>
    public static bool IsValidBase64Url256([ System.Diagnostics.CodeAnalysis.NotNullWhen(true) ] string? value)
    {
        if (value is null || value.Length != Base64Url256Length)
        {
            return false;
        }

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            bool ok = (c >= 'A' && c <= 'Z') ||
                      (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') ||
                      c == '-' ||
                      c == '_';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Encodes <paramref name="bytes"/> as unpadded base64url (<c>B64U</c>).
    /// </summary>
    public static string ToBase64Url(ReadOnlySpan<byte> bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
