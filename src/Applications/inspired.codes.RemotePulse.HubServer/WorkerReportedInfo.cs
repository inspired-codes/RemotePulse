using System.Text.RegularExpressions;

namespace InspiredCodes.RemotePulse.HubServer;

/// <summary>
/// Normalizes what a Worker self-reports in X-Worker-Version / X-Worker-Capabilities before it
/// is stored and handed to the App.
/// </summary>
/// <remarks>
/// Only called on the signature-verified path, but the values are still Worker-supplied text that
/// lands in the DB and in /api/clients/status - so they're length-bounded and reduced to a narrow
/// charset rather than stored verbatim. Anything that doesn't fit is dropped, not truncated: a
/// half-parsed version or token is worse than none.
/// </remarks>
internal static partial class WorkerReportedInfo
{
    public const int MaxVersionLength = 32;
    public const int MaxCapabilityCount = 16;
    public const int MaxTokenLength = 32;

    // Room for MaxCapabilityCount tokens of MaxTokenLength plus the commas between them.
    public const int MaxCapabilitiesLength = MaxCapabilityCount * (MaxTokenLength + 1);

    [GeneratedRegex(@"^[0-9A-Za-z.+-]{1,32}\z")]
    private static partial Regex VersionPattern();

    [GeneratedRegex(@"^[a-z0-9-]{1,32}\z")]
    private static partial Regex TokenPattern();

    /// <summary>Returns the trimmed version, or null if it's missing or not a plain version string.</summary>
    public static string? NormalizeVersion(string? raw)
    {
        string trimmed = raw?.Trim() ?? string.Empty;
        return VersionPattern().IsMatch(trimmed) ? trimmed : null;
    }

    /// <summary>
    /// Returns the valid tokens, lowercased, de-duplicated and comma-joined in their original
    /// order, or null if none are valid.
    /// </summary>
    public static string? NormalizeCapabilities(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        List<string> tokens = raw
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.ToLowerInvariant())
            .Where(t => TokenPattern().IsMatch(t))
            .Distinct(StringComparer.Ordinal)
            .Take(MaxCapabilityCount)
            .ToList();

        return tokens.Count == 0 ? null : string.Join(',', tokens);
    }

    /// <summary>Splits the stored comma-joined form back into tokens for the wire.</summary>
    public static IReadOnlyList<string>? SplitCapabilities(string? stored) =>
        string.IsNullOrEmpty(stored) ? null : stored.Split(',');
}
