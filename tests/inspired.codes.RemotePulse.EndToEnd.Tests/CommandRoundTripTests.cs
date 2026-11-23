using System.Security.Cryptography;
using InspiredCodes.RemotePulse.Shared.Contracts;
using Xunit;

namespace InspiredCodes.RemotePulse.EndToEnd.Tests;

/// <summary>
/// The full App → Hub → Worker → PowerShell → Hub → App round trip, in process.
/// In Phase 1 E2E encryption, command execution results are encrypted on the Worker with the per-command ReplyKey
/// and decrypted on the App, with zero plaintext outputs stored on the Hub.
/// </summary>
public class CommandRoundTripTests
{
    [Fact]
    public async Task QueuedCommand_ShouldBeDecryptedExecutedAndReportedBack()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        string commandId = await sut.QueueCommandAsync(
            "Write-Output 'E2E-MARKER-4711'",
            ExecutionMode.RunWithHighestLocalPrivileges);

        // Nothing has run yet - the command is sitting in the Hub's queue.
        Assert.Null(await sut.GetResultAsync(commandId));

        await sut.RunWorkerCycleAsync();

        var rawResult = await sut.GetResultAsync(commandId);
        Assert.NotNull(rawResult);
        Assert.True(rawResult.IsEncrypted, "Result from Worker to Hub must be encrypted.");
        Assert.NotNull(rawResult.EncryptedPayload);

        var decrypted = await sut.GetDecryptedResultAsync(commandId);
        Assert.NotNull(decrypted);
        Assert.True(decrypted.Success, $"Expected success. Error was: {decrypted.Error}");

        // Real PowerShell really ran: this string only exists because the engine executed it.
        Assert.Contains("E2E-MARKER-4711", decrypted.Output);
    }

    [Fact]
    public async Task CommandSignedByAnUnknownApp_ShouldBeRejectedAndNeverExecuted()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        // An attacker who can somehow queue on the Hub still can't get code run: the Worker
        // verifies the inner script signature against the App keys it has locally paired with.
        using var forgedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string marker = "SHOULD-NEVER-RUN-" + Guid.NewGuid().ToString("N")[..8];
        string commandId = await sut.QueueCommandAsync(
            $"Write-Output '{marker}'",
            ExecutionMode.RunWithHighestLocalPrivileges,
            signingKey: forgedKey);

        await sut.RunWorkerCycleAsync();

        var result = await sut.GetResultAsync(commandId);
        Assert.NotNull(result);
        Assert.False(result.Success, "A command signed by an unpaired App must not succeed.");
        Assert.False(result.IsEncrypted, "A rejection result from envelope validation is unencrypted.");
        Assert.Equal("SignatureInvalid", result.RejectionReason);
    }

    [Fact]
    public async Task FailingScript_ShouldRoundTripTheErrorRatherThanReportingSuccess()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        string commandId = await sut.QueueCommandAsync(
            "Write-Error 'deliberate failure'",
            ExecutionMode.RunWithHighestLocalPrivileges);

        await sut.RunWorkerCycleAsync();

        var rawResult = await sut.GetResultAsync(commandId);
        Assert.NotNull(rawResult);
        Assert.True(rawResult.IsEncrypted);

        var decrypted = await sut.GetDecryptedResultAsync(commandId);
        Assert.NotNull(decrypted);
        Assert.False(decrypted.Success);
        Assert.Contains("deliberate failure", decrypted.Error);
    }

    [Fact]
    public async Task ExecutionMode_ShouldSurviveTheWholeRoundTrip()
    {
        using var sut = new RemotePulseFixture();
        await sut.PairAsync();

        string commandId = await sut.QueueCommandAsync(
            "Write-Output \"ran-as-$([Environment]::UserName)\"",
            ExecutionMode.RunAsCurrentUser);

        await sut.RunWorkerCycleAsync();

        var rawResult = await sut.GetResultAsync(commandId);
        Assert.NotNull(rawResult);
        Assert.True(rawResult.IsEncrypted);

        var decrypted = await sut.GetDecryptedResultAsync(commandId);
        Assert.NotNull(decrypted);
        Assert.True(decrypted.Success, $"Expected success. Error was: {decrypted.Error}");
        Assert.Contains("ran-as-", decrypted.Output);
    }
}
