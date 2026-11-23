using System.Threading.Tasks;
using InspiredCodes.RemotePulse.Shared.Contracts;

namespace InspiredCodes.Client.PowerShellEngine;

public interface IPowerShellEngine
{
    /// <summary>
    /// Executes a PowerShell script in-process.
    /// </summary>
    /// <param name="script">The PowerShell script text to run.</param>
    /// <param name="executionMode">
    /// The Windows security context to execute under. See <see cref="ExecutionMode"/> for the
    /// three supported modes (thread impersonation, interactive session launch, or direct SYSTEM).
    /// </param>
    /// <returns>A structured execution result containing stream collections and status.</returns>
    Task<PowerShellResult> ExecuteScriptAsync(string script, ExecutionMode executionMode, TimeSpan? timeout = null);
}
