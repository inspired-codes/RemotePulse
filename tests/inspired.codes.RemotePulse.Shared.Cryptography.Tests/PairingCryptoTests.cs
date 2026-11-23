using System;
using System.Security.Cryptography;
using Xunit;

namespace InspiredCodes.RemotePulse.Shared.Cryptography.Tests;

public class PairingCryptoTests
{
    public const string FixedSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    public const string FixedWorkerSpkiBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345==";
    public const string FixedAppSpkiBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba==";
    public const string FixedAppId = "11111111-2222-3333-4444-555555555555";

    public const string ExpectedPairingId = "OKgkQlePh8iD9qBa1Q0gxvZSkCGrUNwXRP505J14_4I";
    public const string ExpectedBindKeyHex = "8AED5185897322EFE51F5AA5F20AE10787E8A3A5A6BEC56C25D31C725CFAECB9"; // gitleaks:allow (known-answer test vector, not a secret)
    public const string ExpectedWorkerFingerprint = "NQUKhbZw31YXJu2f2H8AbLd5A4P1Sf6pJeta0z4Hq4g";
    public const string ExpectedAppBindTag = "1oVaV4YjQAvNkBHBvDnsbq1iw3cS4waVByRECMqPHns";
    public const string ExpectedSafetyCode = "475 952";

    [Fact]
    public void KnownAnswer_DerivePairingId_MatchesKnownAnswerVector()
    {
        string pid = PairingCrypto.DerivePairingId(FixedSecret);
        Assert.Equal(ExpectedPairingId, pid);
        Assert.True(PairingCrypto.IsValidBase64Url256(pid));
    }

    [Fact]
    public void KnownAnswer_DeriveBindKey_MatchesKnownAnswerVector()
    {
        byte[] bindKey = PairingCrypto.DeriveBindKey(FixedSecret);
        Assert.Equal(ExpectedBindKeyHex, Convert.ToHexString(bindKey));
    }

    [Fact]
    public void KnownAnswer_ComputePublicKeyFingerprint_MatchesSha256Vector()
    {
        string fp = PairingCrypto.ComputePublicKeyFingerprint(FixedWorkerSpkiBase64);
        Assert.Equal(ExpectedWorkerFingerprint, fp);
        Assert.True(PairingCrypto.VerifyPublicKeyFingerprint(FixedWorkerSpkiBase64, ExpectedWorkerFingerprint));
    }

    [Fact]
    public void KnownAnswer_ComputeAppBindTag_MatchesHmacSha256Vector()
    {
        string tag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64);

        Assert.Equal(ExpectedAppBindTag, tag);
        Assert.True(PairingCrypto.VerifyAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64,
            ExpectedAppBindTag));
    }

    [Fact]
    public void KnownAnswer_ComputeSafetyCode_MatchesSha256BigEndianModVector()
    {
        string sas = PairingCrypto.ComputeSafetyCode(FixedWorkerSpkiBase64, FixedAppSpkiBase64);
        Assert.Equal(ExpectedSafetyCode, sas);
    }

    [Fact]
    public void ComputeAppBindTag_ChangesWhenAnySingleInputChanges_AndVerifyRejects()
    {
        string validTag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64);

        string diffSecretTag = PairingCrypto.ComputeAppBindTag(
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64);

        string diffPidTag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            "BKgkQlePh8iD9qBa1Q0gxvZSkCGrUNwXRP505J14_4I",
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64);

        string diffFpTag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            PairingCrypto.ComputePublicKeyFingerprint(FixedAppSpkiBase64),
            FixedAppId,
            FixedAppSpkiBase64);

        string diffAppIdTag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            "99999999-2222-3333-4444-555555555555",
            FixedAppSpkiBase64);

        string diffAppKeyTag = PairingCrypto.ComputeAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedWorkerSpkiBase64);

        Assert.NotEqual(validTag, diffSecretTag);
        Assert.NotEqual(validTag, diffPidTag);
        Assert.NotEqual(validTag, diffFpTag);
        Assert.NotEqual(validTag, diffAppIdTag);
        Assert.NotEqual(validTag, diffAppKeyTag);

        Assert.False(PairingCrypto.VerifyAppBindTag(
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64,
            validTag));

        Assert.False(PairingCrypto.VerifyAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            PairingCrypto.ComputePublicKeyFingerprint(FixedAppSpkiBase64),
            FixedAppId,
            FixedAppSpkiBase64,
            validTag));

        Assert.False(PairingCrypto.VerifyAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedWorkerSpkiBase64,
            validTag));

        Assert.False(PairingCrypto.VerifyAppBindTag(
            FixedSecret,
            ExpectedPairingId,
            ExpectedWorkerFingerprint,
            FixedAppId,
            FixedAppSpkiBase64,
            "too-short"));
    }

    [Fact]
    public void VerifyPublicKeyFingerprint_RejectsSwappedOrMalformedKey()
    {
        Assert.False(PairingCrypto.VerifyPublicKeyFingerprint(FixedAppSpkiBase64, ExpectedWorkerFingerprint));
        Assert.False(PairingCrypto.VerifyPublicKeyFingerprint("not-base64!!!", ExpectedWorkerFingerprint));
        Assert.False(PairingCrypto.VerifyPublicKeyFingerprint(FixedWorkerSpkiBase64, "short"));
        Assert.False(PairingCrypto.VerifyPublicKeyFingerprint(null, ExpectedWorkerFingerprint));
    }

    [Fact]
    public void ComputeSafetyCode_OrderMatters_AndChangesWhenEitherKeyChanges()
    {
        string sasNormal = PairingCrypto.ComputeSafetyCode(FixedWorkerSpkiBase64, FixedAppSpkiBase64);
        string sasReversed = PairingCrypto.ComputeSafetyCode(FixedAppSpkiBase64, FixedWorkerSpkiBase64);

        Assert.NotEqual(sasNormal, sasReversed);
        Assert.Matches(@"^\d{3} \d{3}$", sasNormal);
        Assert.Matches(@"^\d{3} \d{3}$", sasReversed);
    }

    [Fact]
    public void GenerateSecret_ProducesValid43CharBase64Url_AndUniqueValues()
    {
        string s1 = PairingCrypto.GenerateSecret();
        string s2 = PairingCrypto.GenerateSecret();

        Assert.True(PairingCrypto.IsValidBase64Url256(s1));
        Assert.True(PairingCrypto.IsValidBase64Url256(s2));
        Assert.NotEqual(s1, s2);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("short", false)]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)] // '=' not allowed
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+", false)] // '+' not base64url
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/", false)] // '/' not base64url
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true)]
    [InlineData("0123456789abcdefghijklmnopqrstuvwxyzABCDE-_", true)]
    public void IsValidBase64Url256_ValidatesLengthAndAlphabet(string? candidate, bool expected)
    {
        Assert.Equal(expected, PairingCrypto.IsValidBase64Url256(candidate));
    }
}
