using System;
using InspiredCodes.RemotePulse.App.Pages;
using InspiredCodes.RemotePulse.App.Services;
using InspiredCodes.RemotePulse.Shared.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.App.Tests;

public class PairingLinkParserTests
{
    private const string ValidFp = "NQUKhbZw31YXJu2f2H8AbLd5A4P1Sf6pJeta0z4Hq4g";
    private const string ValidSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    [Fact]
    public void TryParse_V2BareFragment_ReturnsVersion2SecretFingerprintAndTimestamp()
    {
        string text = $"#k={ValidSecret}&fp={ValidFp}&ts=2026-10-27T17:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Equal(ValidFp, result.WorkerFingerprint);
        Assert.Equal(DateTimeOffset.Parse("2026-10-27T17:00:00Z"), result.GeneratedAtUtc);
        Assert.Null(result.HubOrigin);
    }

    [Fact]
    public void TryParse_V2FullAbsoluteUrl_ReturnsParsedValuesAndHubOrigin()
    {
        string text = $"https://rmpls.inspired.codes:8443/pairing/v2#k={ValidSecret}&fp={ValidFp}&ts=2026-10-27T15:30:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Equal(ValidFp, result.WorkerFingerprint);
        Assert.Equal(DateTimeOffset.Parse("2026-10-27T15:30:00Z"), result.GeneratedAtUtc);
        Assert.Equal("https://rmpls.inspired.codes:8443", result.HubOrigin);
    }

    [Theory]
    [InlineData("#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&ts=2026-10-27T17:00:00Z")]
    [InlineData("#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=&ts=2026-10-27T17:00:00Z")]
    [InlineData("#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=too-short&ts=2026-10-27T17:00:00Z")]
    [InlineData("#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&ts=2026-10-27T17:00:00Z")]
    [InlineData("#k=&fp=NQUKhbZw31YXJu2f2H8AbLd5A4P1Sf6pJeta0z4Hq4g&ts=2026-10-27T17:00:00Z")]
    public void TryParse_V2MissingOrInvalidFingerprintOrKey_ReturnsFalse(string text)
    {
        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_V1BareFragment_ReturnsVersion1AndNullFingerprint()
    {
        string text = "#secret=my-secret-token-123&ts=2026-09-03T17:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(1, result.Version);
        Assert.Equal("my-secret-token-123", result.Secret);
        Assert.Null(result.WorkerFingerprint);
        Assert.Equal(DateTimeOffset.Parse("2026-09-03T17:00:00Z"), result.GeneratedAtUtc);
        Assert.Null(result.HubOrigin);
    }

    [Fact]
    public void TryParse_V1FullAbsoluteUrl_ReturnsVersion1AndHubOrigin()
    {
        string text = "https://rmpls.inspired.codes:8443/pairing/v1#secret=alpha-node-secret&ts=2026-09-03T15:30:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(1, result.Version);
        Assert.Equal("alpha-node-secret", result.Secret);
        Assert.Null(result.WorkerFingerprint);
        Assert.Equal(DateTimeOffset.Parse("2026-09-03T15:30:00Z"), result.GeneratedAtUtc);
        Assert.Equal("https://rmpls.inspired.codes:8443", result.HubOrigin);
    }

    [Fact]
    public void Scan_GetNavigationTargetForScannedLink_RoutesV2ToPairingV2_AndV1ToPairingV1()
    {
        string v2Url = $"https://psrun.inspired.codes/pairing/v2#k={ValidSecret}&fp={ValidFp}&ts=2026-10-27T17:00:00Z";
        string? v2Target = Scan.GetNavigationTargetForScannedLink(v2Url);
        Assert.Equal($"/pairing/v2#k={ValidSecret}&fp={ValidFp}&ts=2026-10-27T17:00:00Z", v2Target);

        string v1Url = "https://psrun.inspired.codes/pairing/v1#secret=old-secret&ts=2026-10-27T17:00:00Z";
        string? v1Target = Scan.GetNavigationTargetForScannedLink(v1Url);
        Assert.Equal("/pairing/v1#secret=old-secret&ts=2026-10-27T17:00:00Z", v1Target);

        Assert.Null(Scan.GetNavigationTargetForScannedLink("https://psrun.inspired.codes/not-a-pairing-link"));
        Assert.Null(Scan.GetNavigationTargetForScannedLink($"https://psrun.inspired.codes/pairing/v2#k={ValidSecret}&ts=2026-10-27T17:00:00Z"));
    }

    [Fact]
    public void TryParse_UrlWithAppSubpath_ExtractsAuthorityCorrectly()
    {
        string text = $"https://rmpls.inspired.codes/app/scan/#k={ValidSecret}&fp={ValidFp}&ts=2026-09-03T12:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Equal("https://rmpls.inspired.codes", result.HubOrigin);
    }

    [Fact]
    public void TryParse_UrlEscapedSecret_UnescapesSpecialCharactersCorrectly()
    {
        string text = "#secret=abc%2Bdef%2Fghi%3D%3D&ts=2026-09-03T10:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(1, result.Version);
        Assert.Equal("abc+def/ghi==", result.Secret);
    }

    [Fact]
    public void TryParse_NonUtcTimezoneOffset_ParsesToEquivalentUtcInstant()
    {
        string text = $"#k={ValidSecret}&fp={ValidFp}&ts=2026-09-03T19:00:00+02:00";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(DateTimeOffset.Parse("2026-09-03T17:00:00Z"), result.GeneratedAtUtc.ToUniversalTime());
    }

    [Fact]
    public void TryParse_ExtraUnknownParameters_IgnoresExtrasAndSucceeds()
    {
        string text = $"#role=worker&k={ValidSecret}&fp={ValidFp}&ts=2026-09-03T16:00:00Z&extra=123";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Equal(ValidFp, result.WorkerFingerprint);
        Assert.Equal(DateTimeOffset.Parse("2026-09-03T16:00:00Z"), result.GeneratedAtUtc);
    }

    [Fact]
    public void TryParse_ReversedParameterOrder_Succeeds()
    {
        string text = $"#ts=2026-09-03T16:00:00Z&fp={ValidFp}&k={ValidSecret}";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Equal(ValidFp, result.WorkerFingerprint);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryParse_NullOrWhitespace_ReturnsFalse(string? input)
    {
        bool success = PairingLinkParser.TryParse(input, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_MissingHashFragment_ReturnsFalse()
    {
        string text = "https://rmpls.inspired.codes/pairing/v2";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_EmptyFragment_ReturnsFalse()
    {
        string text = "https://rmpls.inspired.codes/pairing/v2#";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_MissingSecretAndKey_ReturnsFalse()
    {
        string text = "#ts=2026-09-03T16:00:00Z&role=worker";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_EmptySecretValue_ReturnsFalse()
    {
        string text = "#secret=&ts=2026-09-03T16:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_MissingTimestamp_ReturnsFalse()
    {
        string text = $"#k={ValidSecret}&fp={ValidFp}&foo=bar";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_MalformedTimestamp_ReturnsFalse()
    {
        string text = $"#k={ValidSecret}&fp={ValidFp}&ts=not-a-valid-datetime";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.False(success);
        Assert.Null(result);
    }

    [Fact]
    public void TryParse_MalformedKeyValuePairsInFragment_SkipsMalformedAndExtractsValid()
    {
        string text = $"#malformed_key_value&k={ValidSecret}&fp={ValidFp}&another-bad=&ts=2026-09-03T16:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
    }

    [Fact]
    public void TryParse_RelativeUrlBeforeHash_ReturnsNullHubOrigin()
    {
        string text = $"/pairing/v2#k={ValidSecret}&fp={ValidFp}&ts=2026-09-03T16:00:00Z";

        bool success = PairingLinkParser.TryParse(text, out var result);

        Assert.True(success);
        Assert.NotNull(result);
        Assert.Equal(2, result.Version);
        Assert.Equal(ValidSecret, result.Secret);
        Assert.Null(result.HubOrigin);
    }
}
