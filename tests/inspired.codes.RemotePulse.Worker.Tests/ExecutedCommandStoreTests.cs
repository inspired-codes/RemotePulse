using InspiredCodes.RemotePulse.Worker;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace InspiredCodes.RemotePulse.Worker.Tests;

/// <summary>
/// SEC-1 replay store: an executed envelope must stay recorded for as long as it could still pass
/// the 5-minute freshness check - by age, never by count.
/// </summary>
public sealed class ExecutedCommandStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"remotepulse_replay_test_{Guid.NewGuid():N}");
    private DateTimeOffset _now = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

    private string FilePath => Path.Combine(_dir, "executed-commands.json");

    private ExecutedCommandStore NewStore() => new(FilePath, NullLogger.Instance, () => _now);

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public void Record_ThenContains_MatchesOnlyThatCommandAndNonce()
    {
        var store = NewStore();

        store.Record("CMD-1", "nonce-a");

        Assert.True(store.Contains("CMD-1", "nonce-a"));
        Assert.False(store.Contains("CMD-1", "nonce-b"));
        Assert.False(store.Contains("CMD-2", "nonce-a"));
    }

    [Fact]
    public void Record_SurvivesARestart()
    {
        NewStore().Record("CMD-1", "nonce-a");

        Assert.True(NewStore().Contains("CMD-1", "nonce-a"));
    }

    [Fact]
    public void Entry_IsKeptForTheWholeRetention_ThenDroppedOnTheNextRecord()
    {
        var store = NewStore();
        store.Record("CMD-OLD", "n");

        _now += ExecutedCommandStore.Retention;
        store.Record("CMD-2", "n");
        Assert.True(store.Contains("CMD-OLD", "n"));

        _now += TimeSpan.FromSeconds(1);
        store.Record("CMD-3", "n");
        Assert.False(store.Contains("CMD-OLD", "n"));
        Assert.True(store.Contains("CMD-3", "n"));
    }

    [Fact]
    public void ManyCommandsWithinTheWindow_NeverEvictAStillFreshOne()
    {
        // The old ring kept only the newest 500 - command 1 would have dropped out here while
        // its envelope was still inside the freshness window.
        var store = NewStore();
        for (int i = 1; i <= 600; i++)
        {
            store.Record($"CMD-{i}", "n");
        }

        Assert.True(store.Contains("CMD-1", "n"));
        Assert.True(store.Contains("CMD-600", "n"));
    }

    [Fact]
    public void ClockSteppedBack_KeepsEntriesRecordedLater()
    {
        var store = NewStore();
        store.Record("CMD-1", "n");

        _now -= TimeSpan.FromMinutes(3);
        store.Record("CMD-2", "n");

        Assert.True(store.Contains("CMD-1", "n"));
    }

    [Fact]
    public void OldFormatFile_BareKeys_AreHonouredAndKeptForAFullRetention()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, """["CMD-OLD:nonce-a"]""");
        var store = NewStore();

        Assert.True(store.Contains("CMD-OLD", "nonce-a"));

        // The first Record after the upgrade rewrites the file with times...
        store.Record("CMD-NEW", "n");
        Assert.True(store.Contains("CMD-OLD", "nonce-a"));
        Assert.Contains("\"Key\":\"CMD-OLD:nonce-a\",\"RecordedAtUtc\"", File.ReadAllText(FilePath));

        // ...so the migrated entry expires like any other.
        _now += ExecutedCommandStore.Retention + TimeSpan.FromSeconds(1);
        store.Record("CMD-LATER", "n");
        Assert.False(store.Contains("CMD-OLD", "nonce-a"));
    }

    [Fact]
    public void CorruptFile_IsTreatedAsEmpty_AndRewrittenOnTheNextRecord()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(FilePath, "{ not json");
        var store = NewStore();

        Assert.False(store.Contains("CMD-1", "n"));

        store.Record("CMD-1", "n");
        Assert.True(store.Contains("CMD-1", "n"));
    }
}
