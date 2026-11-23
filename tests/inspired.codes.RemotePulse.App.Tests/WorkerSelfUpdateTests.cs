using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

/// <summary>
/// The "Update Worker" command as the App sends it. The script's own behaviour is covered in
/// the PowerShellEngine tests, which can actually parse and run it.
/// </summary>
public class WorkerSelfUpdateTests
{
    [Fact]
    public void Script_IsEmbeddedInTheAppBuild()
    {
        string script = WorkerSelfUpdate.Script;

        Assert.StartsWith("<#", script);
        Assert.Contains("RemotePulse Worker Self-Update", script);
        Assert.Contains("systemd-run", script);
    }

    [Fact]
    public void Command_AlwaysRunsAsSystemOrRoot()
    {
        // Any other mode runs as the logged-on user, who can't replace the Worker; the script
        // refuses there, so the App must never send it that way.
        Assert.Equal(ExecutionMode.RunWithHighestLocalPrivileges, WorkerSelfUpdate.Mode);
    }
}
