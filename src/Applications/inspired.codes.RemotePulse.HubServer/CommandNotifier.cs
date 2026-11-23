using System.Collections.Concurrent;

namespace InspiredCodes.RemotePulse.HubServer;

/// <summary>
/// Wakes a parked long-poll the moment work is queued for its machine, instead of leaving it to
/// discover the command on its next re-check.
/// </summary>
/// <remarks>
/// In-memory, so signals only reach waiters on the same Hub instance. That is deliberate rather
/// than an oversight: the deployment runs a single Hub container, and the long-poll loop re-checks
/// the database periodically regardless, so a signal that never arrives costs a few seconds of
/// latency rather than a lost command. Moving to multiple Hub instances would want Postgres
/// LISTEN/NOTIFY or Redis here - the re-check is what keeps that a performance change rather than
/// a correctness one.
/// </remarks>
public sealed class CommandNotifier
{
    private readonly ConcurrentDictionary<string, TaskCompletionSource> _waiters = new(StringComparer.Ordinal);

    /// <summary>
    /// Signals that work is available for a machine. Safe to call for machines nobody is waiting
    /// on - that is the normal case when the Worker is between polls.
    /// </summary>
    public void Notify(string machineId)
    {
        if (_waiters.TryRemove(machineId, out TaskCompletionSource? tcs))
        {
            tcs.TrySetResult();
        }
    }

    /// <summary>
    /// Registers interest in a machine's queue, returning a subscription to await.
    /// </summary>
    /// <remarks>
    /// Subscribe <em>before</em> querying the database, then await only if the query came back
    /// empty. Doing it the other way round loses any command queued between the two steps: the
    /// signal fires while nobody is registered, and the poll then parks despite work being ready.
    /// The two-step shape exists to make that ordering the natural one to write.
    /// </remarks>
    public Subscription Subscribe(string machineId)
    {
        TaskCompletionSource tcs = _waiters.GetOrAdd(
            machineId,
            _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        return new Subscription(this, machineId, tcs);
    }

    private void Unsubscribe(string machineId, TaskCompletionSource tcs)
    {
        // Only drop the entry if it is still ours - a concurrent Notify may already have removed
        // it and a later poll may have registered a fresh one in its place.
        _waiters.TryRemove(new KeyValuePair<string, TaskCompletionSource>(machineId, tcs));
    }

    public sealed class Subscription(CommandNotifier notifier, string machineId, TaskCompletionSource tcs) : IDisposable
    {
        /// <summary>
        /// Waits for a signal, the timeout, or the caller disconnecting. True only when actually
        /// signalled, so the caller can tell "something arrived" from "time to give up".
        /// </summary>
        public async Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancellationToken)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout);

            try
            {
                await tcs.Task.WaitAsync(timeoutCts.Token).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException)
            {
                return false;
            }
        }

        public void Dispose() => notifier.Unsubscribe(machineId, tcs);
    }
}
