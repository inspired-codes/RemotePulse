using System;
using System.Diagnostics.CodeAnalysis;
using InspiredCodes.RemotePulse.Shared.Cryptography;

namespace InspiredCodes.RemotePulse.App.Services;

/// <summary>
/// Parses a co-presence pairing link (see docs/specs/pairing-v2-key-binding-spec.md §4.2),
/// either as a bare URL fragment (e.g. from <c>window.location.hash</c> when the PWA was
/// opened at /pairing/v2 or /pairing/v1) or as a full URL (e.g. the raw text decoded from a
/// QR code scanned inside the app).
/// <para>
/// Version 2 carries <c>#k=&lt;S&gt;&amp;fp=&lt;fp&gt;&amp;ts=&lt;ts&gt;</c> (both <c>k</c> and a valid
/// 43-char base64url <c>fp</c> are required). Version 1 (<c>#secret=&lt;S&gt;&amp;ts=&lt;ts&gt;</c>)
/// is recognized only so the UI can tell the operator to update the Worker without sending
/// anything to the Hub.
/// </para>
/// </summary>
public static class PairingLinkParser
{
    public sealed record ParsedLink(
        int Version,
        string Secret,
        string? WorkerFingerprint,
        DateTimeOffset GeneratedAtUtc,
        string? HubOrigin);

    /// <summary>
    /// Attempts to parse a pairing link. <paramref name="text"/> may be a bare fragment
    /// or a full absolute URL containing one. Returns the Hub's origin (scheme://host:port)
    /// only when a full absolute URL was given - a bare fragment carries no host information.
    /// </summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out ParsedLink? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        string? hubOrigin = null;
        int hashIndex = text.IndexOf('#');
        if (hashIndex < 0)
        {
            return false; // No fragment at all - not a pairing link.
        }

        string beforeHash = text.Substring(0, hashIndex);
        string fragment = text.Substring(hashIndex + 1);

        if (!string.IsNullOrEmpty(beforeHash) &&
            Uri.TryCreate(beforeHash, UriKind.Absolute, out Uri? absoluteUri) &&
            (absoluteUri.Scheme == Uri.UriSchemeHttp || absoluteUri.Scheme == Uri.UriSchemeHttps))
        {
            hubOrigin = absoluteUri.GetLeftPart(UriPartial.Authority);
        }

        string? v2Key = null;
        string? workerFingerprint = null;
        string? v1Secret = null;
        DateTimeOffset? generatedAtUtc = null;

        foreach (string pair in fragment.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] keyValue = pair.Split('=', 2);
            if (keyValue.Length != 2) continue;

            string key = keyValue[0];
            string value = Uri.UnescapeDataString(keyValue[1]);

            if (key == "k")
            {
                v2Key = value;
            }
            else if (key == "fp")
            {
                workerFingerprint = value;
            }
            else if (key == "secret")
            {
                v1Secret = value;
            }
            else if (key == "ts" && DateTimeOffset.TryParse(value, out DateTimeOffset parsedTs))
            {
                generatedAtUtc = parsedTs;
            }
        }

        if (generatedAtUtc == null)
        {
            return false;
        }

        // Pairing v2: requires non-empty k and a valid 43-char base64url Worker fingerprint (fp).
        // A fragment with k but missing or malformed fp is invalid and fails closed.
        if (v2Key != null)
        {
            if (string.IsNullOrWhiteSpace(v2Key) || !PairingCrypto.IsValidBase64Url256(workerFingerprint))
            {
                return false;
            }

            result = new ParsedLink(
                Version: 2,
                Secret: v2Key,
                WorkerFingerprint: workerFingerprint,
                GeneratedAtUtc: generatedAtUtc.Value,
                HubOrigin: hubOrigin);
            return true;
        }

        // Pairing v1: recognized only to show the "update the Worker" message without contacting the Hub.
        if (!string.IsNullOrWhiteSpace(v1Secret))
        {
            result = new ParsedLink(
                Version: 1,
                Secret: v1Secret,
                WorkerFingerprint: null,
                GeneratedAtUtc: generatedAtUtc.Value,
                HubOrigin: hubOrigin);
            return true;
        }

        return false;
    }
}
