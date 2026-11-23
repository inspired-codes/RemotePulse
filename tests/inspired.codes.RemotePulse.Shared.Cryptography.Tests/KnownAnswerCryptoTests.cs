using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace InspiredCodes.RemotePulse.Shared.Cryptography.Tests;

public class KnownAnswerCryptoTests
{
    // Fixed Test Vector Constants
    public const string FixedKeyHex = "4242424242424242424242424242424242424242424242424242424242424242";
    public const string FixedNonceHex = "0102030405060708090A0B0C";
    public const string FixedCommandId = "CMD-TEST-00000001";
    public const string FixedPlaintext = "{\"Success\":true,\"DurationMs\":42.0,\"Output\":\"Hello RemotePulse\",\"Error\":\"\",\"CombinedOutput\":\"Hello RemotePulse\",\"Streams\":null}";

    public const string ExpectedBlobBase64 = "AQIDBAUGBwgJCgsMzth1OS4QLHD/+Iu8OPwL4LL7trRm614d4J+vO6V6PNCZdm2slXRFVBcM6U/LuK/sdWHnHerJr43VdqRuPiwYLr4hWlR7ltU0UqBCS0lZ0h25uM0ewjbo6GKexwYLN3eyEjUceWLJINuzzcI4fmKNP838htDHaijU8oay05HfZfTxColUHyFqv6PipxeoZg==";

    [Fact]
    public void KnownAnswer_Aes256Gcm_EncryptionAndDecryption_DeterministicRoundTrip()
    {
        byte[] key = Convert.FromHexString(FixedKeyHex);
        byte[] nonce = Convert.FromHexString(FixedNonceHex);
        byte[] aad = Encoding.UTF8.GetBytes(FixedCommandId);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(FixedPlaintext);

        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16];

        using (var aesGcm = new AesGcm(key, 16))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, aad);
        }

        // Assemble wire blob format: Nonce (12B) || Ciphertext || Tag (16B)
        byte[] blob = new byte[12 + ciphertext.Length + 16];
        Buffer.BlockCopy(nonce, 0, blob, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, blob, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, blob, 12 + ciphertext.Length, 16);

        string blobBase64 = Convert.ToBase64String(blob);
        Assert.Equal(ExpectedBlobBase64, blobBase64);

        // Decrypt with AesGcm
        byte[] decryptedBytes = new byte[ciphertext.Length];
        using (var decryptAesGcm = new AesGcm(key, 16))
        {
            decryptAesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes, aad);
        }

        string decryptedString = Encoding.UTF8.GetString(decryptedBytes);
        Assert.Equal(FixedPlaintext, decryptedString);
    }

    [Fact]
    public void ResultSwap_TamperedCommandIdAAD_ThrowsAuthenticationTagMismatchException()
    {
        byte[] key = Convert.FromHexString(FixedKeyHex);
        byte[] nonce = Convert.FromHexString(FixedNonceHex);
        byte[] originalAad = Encoding.UTF8.GetBytes(FixedCommandId);
        byte[] tamperedAad = Encoding.UTF8.GetBytes("CMD-TEST-TAMPERED99");
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(FixedPlaintext);

        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16];

        using (var aesGcm = new AesGcm(key, 16))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, originalAad);
        }

        byte[] decryptedBytes = new byte[ciphertext.Length];
        using (var decryptAesGcm = new AesGcm(key, 16))
        {
            // Decrypting with a different commandId (tampered AAD) MUST throw AuthenticationTagMismatchException
            Assert.Throws<AuthenticationTagMismatchException>(() =>
            {
                decryptAesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes, tamperedAad);
            });
        }
    }

    [Fact]
    public void TamperedCiphertext_ThrowsAuthenticationTagMismatchException()
    {
        byte[] key = Convert.FromHexString(FixedKeyHex);
        byte[] nonce = Convert.FromHexString(FixedNonceHex);
        byte[] aad = Encoding.UTF8.GetBytes(FixedCommandId);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(FixedPlaintext);

        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[16];

        using (var aesGcm = new AesGcm(key, 16))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag, aad);
        }

        // Tamper 1 bit in ciphertext
        ciphertext[0] ^= 0x01;

        byte[] decryptedBytes = new byte[ciphertext.Length];
        using (var decryptAesGcm = new AesGcm(key, 16))
        {
            Assert.Throws<AuthenticationTagMismatchException>(() =>
            {
                decryptAesGcm.Decrypt(nonce, ciphertext, tag, decryptedBytes, aad);
            });
        }
    }
}
