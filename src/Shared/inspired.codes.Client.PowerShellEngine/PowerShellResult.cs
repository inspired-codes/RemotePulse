using System;
using System.Collections.Generic;

namespace InspiredCodes.Client.PowerShellEngine;

public sealed class PowerShellResult
{
    /// <summary>
    /// Gets the unique machine ID associated with this execution context.
    /// </summary>
    public string MachineId { get; init; } = string.Empty;

    /// <summary>
    /// Gets a value indicating whether the script ran to completion without unhandled exceptions or error stream writes.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Gets the compiled standard output text.
    /// </summary>
    public string Output { get; init; } = string.Empty;

    /// <summary>
    /// Gets the compiled error stream text.
    /// </summary>
    public string Error { get; init; } = string.Empty;

    /// <summary>
    /// Gets the combined output and error stream text for unified display.
    /// </summary>
    public string CombinedOutput { get; init; } = string.Empty;

    /// <summary>
    /// Gets the list of individual standard output lines.
    /// </summary>
    public IReadOnlyList<string> OutputLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the list of individual error stream entries.
    /// </summary>
    public IReadOnlyList<string> ErrorLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the list of individual warning stream entries.
    /// </summary>
    public IReadOnlyList<string> WarningLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the list of individual information stream entries.
    /// </summary>
    public IReadOnlyList<string> InformationLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the list of individual verbose stream entries.
    /// </summary>
    public IReadOnlyList<string> VerboseLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the list of individual debug stream entries.
    /// </summary>
    public IReadOnlyList<string> DebugLines { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the duration of the script execution.
    /// </summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// Gets the unhandled exception if the execution crashed or failed to initialize.
    /// </summary>
    public Exception? Exception { get; init; }
}
