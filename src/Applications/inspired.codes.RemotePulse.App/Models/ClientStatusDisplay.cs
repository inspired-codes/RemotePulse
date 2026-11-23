using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.RemotePulse.App.Models;

/// <summary>
/// Turns a <see cref="ClientStatus"/> into the CSS classes and wording the UI shows.
/// </summary>
/// <remarks>
/// Lives here rather than inside Index.razor so the mapping can be tested directly. It encodes
/// two distinctions that are easy to regress into a single misleading red: a machine that has
/// merely missed a poll or two is amber, not red; and "we can't reach the Hub" is neutral grey,
/// because that is the phone's problem rather than the client PC's.
/// </remarks>
public static class ClientStatusDisplay
{
    public static string DotClass(ClientStatus status)
    {
        if (status.HubUnreachable) return "unknown";
        return status.Health switch
        {
            ClientHealth.Online => "online",
            ClientHealth.Degraded => "degraded",
            _ => "offline"
        };
    }

    /// <param name="hasWatchdogResult">
    /// False until the watchdog completes its first cycle, so a cold start reads "Checking..."
    /// rather than accusing the Hub of being unreachable before we've actually tried.
    /// </param>
    public static string BadgeText(ClientStatus status, bool hasWatchdogResult)
    {
        if (status.HubUnreachable)
        {
            return hasWatchdogResult ? "Hub Unreachable" : "Checking...";
        }
        return status.Health switch
        {
            ClientHealth.Online => "Online",
            ClientHealth.Degraded => "Unstable",
            _ => "Offline"
        };
    }

    public static string Tooltip(ClientStatus status, bool hasWatchdogResult)
    {
        if (status.HubUnreachable)
        {
            return hasWatchdogResult
                ? "Can't reach the Hub - the client's availability is unknown."
                : "Checking availability...";
        }

        if (status.LastSeenUtc == null || status.SecondsSinceLastSeen == null)
        {
            return "Never checked in since it was registered.";
        }

        string age = $"Last seen {HumanizeAge(status.SecondsSinceLastSeen.Value)}";

        // Naming the missed count is what makes amber actionable - "missed 2 check-ins" tells you
        // it's slipping, where a bare colour change doesn't.
        if (status.Health == ClientHealth.Degraded && status.MissedPolls is int missed and > 0)
        {
            return $"{age} - missed {missed} check-{(missed == 1 ? "in" : "ins")}.";
        }

        return age;
    }

    /// <summary>
    /// "Worker 1.2.0" for the client card - what confirms a remote update actually landed.
    /// Empty for a Worker older than 1.2.0 (it reports no version) and while the Hub can't be
    /// reached, since then we have no fresh report.
    /// </summary>
    public static string WorkerVersionText(ClientStatus status) =>
        status.HubUnreachable || string.IsNullOrEmpty(status.WorkerVersion)
            ? string.Empty
            : $"Worker {status.WorkerVersion}";

    /// <summary>
    /// The short last-seen line under the Worker node, e.g. "seen 35s ago". Empty when there is
    /// no recorded status or the Hub can't be reached - the chain caption explains those cases,
    /// and an age we couldn't refresh would be stale.
    /// </summary>
    public static string LastSeenShort(ClientStatus? status)
    {
        if (status == null || status.HubUnreachable) return string.Empty;
        if (status.LastSeenUtc == null || status.SecondsSinceLastSeen == null) return "never seen";
        return $"seen {HumanizeAge(status.SecondsSinceLastSeen.Value)}";
    }

    /// <summary>
    /// The chain caption once the Hub has answered for the active client. Online needs no
    /// caption - the green dots and the last-seen line say it.
    /// </summary>
    public static string WorkerCaption(ClientStatus status) => status.Health switch
    {
        ClientHealth.Online => string.Empty,
        ClientHealth.Degraded when status.MissedPolls is int missed and > 0 =>
            $"The Worker missed {missed} check-{(missed == 1 ? "in" : "ins")}.",
        ClientHealth.Degraded => "The Worker is missing check-ins.",
        _ => "The Worker is offline."
    };

    /// <summary>
    /// The Hub's host name as the Active Connection panel shows it: no scheme or path, and the
    /// port only when it isn't the scheme's default (so local dev still reads "localhost:54971").
    /// Empty when the URL is missing or unparsable - the UI then shows plain "Hub".
    /// </summary>
    public static string HubHost(string? serverUrl)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out Uri? uri) || string.IsNullOrEmpty(uri.Host))
        {
            return string.Empty;
        }
        return uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
    }

    /// <summary>
    /// The Hub node's dot. With an active client it reflects that client's own Hub, because the
    /// panel names that Hub - the app-wide <paramref name="hubReachable"/> only says whether
    /// *any* paired Hub answered, which with clients on two Hubs can be green while the named one
    /// is down.
    /// </summary>
    /// <param name="activeStatus">
    /// The active client's last watchdog status, or null when there is none yet (e.g. just
    /// paired) - a missing status must not read as "Hub unreachable".
    /// </param>
    public static string HubDot(bool deviceOnline, bool? hubReachable, bool hasWatchdogResult, ClientStatus? activeStatus)
    {
        if (!deviceOnline) return "unknown";
        if (activeStatus != null && hasWatchdogResult)
        {
            return activeStatus.HubUnreachable ? "offline" : "online";
        }
        return hubReachable switch { true => "online", false => "offline", null => "unknown" };
    }

    /// <summary>
    /// Formats a Hub-computed age. Never derives the age locally - a phone's clock can be minutes
    /// off the Hub's, which would otherwise produce nonsense like "last seen in 3 minutes".
    /// </summary>
    public static string HumanizeAge(double seconds)
    {
        if (seconds < 10) return "just now";
        if (seconds < 60) return $"{(int)seconds}s ago";
        if (seconds < 3600) return $"{(int)(seconds / 60)}m ago";
        if (seconds < 86400) return $"{(int)(seconds / 3600)}h ago";
        return $"{(int)(seconds / 86400)}d ago";
    }
}
