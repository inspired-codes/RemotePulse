using System;
using System.Security.Cryptography;
using System.Text;

namespace InspiredCodes.RemotePulse.Shared.Cryptography;

/// <summary>
/// Provides hybrid encryption combining AES-256-GCM (symmetric, for payload) with
/// ECDH Ephemeral-Static P-256 (asymmetric, for key exchange). This allows encrypting payloads
/// of arbitrary length using an EC public key.
///
/// Wire format v3 (binary, concatenated):
///   [65 bytes] Ephemeral ECDH Public Key (0x04 || X || Y) - also passed as AEAD associatedData
///   [12 bytes] AES-GCM nonce/IV
///   [16 bytes] AES-GCM authentication tag
///   [M bytes]  AES-GCM ciphertext
/// </summary>
public static class HybridCrypto
{
    private const int GcmNonceSize = 12; // Standard GCM nonce
    private const int GcmTagSize = 16;   // Standard GCM auth tag
    private const int EphemeralKeySize = 65; // Uncompressed P-256 public key (0x04 + 32 + 32)
    private const int AesKeySize = 32;   // AES-256
    
    private static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("RemotePulse-v3");

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using AES-256-GCM. The AES key is derived
    /// using ECDH key agreement between a fresh ephemeral P-256 key and the recipient's static public key.
    /// </summary>
    /// <param name="plaintext">The data to encrypt.</param>
    /// <param name="recipientPublicKeyBase64">Base64-encoded SPKI EC public key of the recipient.</param>
    /// <returns>The hybrid-encrypted ciphertext blob.</returns>
    public static byte[] Encrypt(byte[] plaintext, string recipientPublicKeyBase64)
    {
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        if (string.IsNullOrWhiteSpace(recipientPublicKeyBase64))
            throw new ArgumentException("Recipient public key is required.", nameof(recipientPublicKeyBase64));

        using var recipientEcdh = ECDiffieHellman.Create();
        recipientEcdh.ImportSubjectPublicKeyInfo(Convert.FromBase64String(recipientPublicKeyBase64), out _);

        using var ephemeralEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        
        // We need to extract the raw uncompressed 65-byte point for the wire format.
        var ecParams = ephemeralEcdh.ExportParameters(false);
        byte[] rawEphemeralKey = new byte[65];
        rawEphemeralKey[0] = 0x04;
        Buffer.BlockCopy(ecParams.Q.X!, 0, rawEphemeralKey, 1, 32);
        Buffer.BlockCopy(ecParams.Q.Y!, 0, rawEphemeralKey, 33, 32);

        byte[] sharedSecret = ephemeralEcdh.DeriveRawSecretAgreement(recipientEcdh.PublicKey);
        byte[] aesKey;
        try
        {
            aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt: Array.Empty<byte>(), info: HkdfInfo);
        }
        finally
        {
            // The raw ECDH agreement is at least as sensitive as the AES key it derives - zero
            // it as soon as HKDF has consumed it, on every path including a thrown exception.
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        try
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(GcmNonceSize);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[GcmTagSize];

            using (var aesGcm = new AesGcm(aesKey, GcmTagSize))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: rawEphemeralKey);
            }

            int totalLength = EphemeralKeySize + GcmNonceSize + GcmTagSize + ciphertext.Length;
            byte[] result = new byte[totalLength];
            int offset = 0;

            Buffer.BlockCopy(rawEphemeralKey, 0, result, offset, EphemeralKeySize);
            offset += EphemeralKeySize;

            Buffer.BlockCopy(nonce, 0, result, offset, GcmNonceSize);
            offset += GcmNonceSize;

            Buffer.BlockCopy(tag, 0, result, offset, GcmTagSize);
            offset += GcmTagSize;

            Buffer.BlockCopy(ciphertext, 0, result, offset, ciphertext.Length);

            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    /// <summary>
    /// Decrypts a hybrid-encrypted blob using the recipient's EC private key.
    /// </summary>
    /// <param name="encryptedBlob">The hybrid-encrypted ciphertext blob.</param>
    /// <param name="recipientEcdh">An ECDiffieHellman instance loaded with the recipient's private key.</param>
    /// <returns>The decrypted plaintext.</returns>
    public static byte[] Decrypt(byte[] encryptedBlob, ECDiffieHellman recipientEcdh)
    {
        if (encryptedBlob == null) throw new ArgumentNullException(nameof(encryptedBlob));
        if (recipientEcdh == null) throw new ArgumentNullException(nameof(recipientEcdh));
        
        int minimumLength = EphemeralKeySize + GcmNonceSize + GcmTagSize;
        if (encryptedBlob.Length < minimumLength)
            throw new CryptographicException("Encrypted blob is too short.");

        int offset = 0;

        byte[] rawEphemeralKey = new byte[EphemeralKeySize];
        Buffer.BlockCopy(encryptedBlob, offset, rawEphemeralKey, 0, EphemeralKeySize);
        offset += EphemeralKeySize;

        if (rawEphemeralKey[0] != 0x04)
            throw new CryptographicException("Invalid ephemeral public key format.");

        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = new byte[32],
                Y = new byte[32]
            }
        };
        Buffer.BlockCopy(rawEphemeralKey, 1, ecParams.Q.X, 0, 32);
        Buffer.BlockCopy(rawEphemeralKey, 33, ecParams.Q.Y, 0, 32);

        using var ephemeralEcdh = ECDiffieHellman.Create(ecParams);

        byte[] sharedSecret = recipientEcdh.DeriveRawSecretAgreement(ephemeralEcdh.PublicKey);
        byte[] aesKey;
        try
        {
            aesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, salt: Array.Empty<byte>(), info: HkdfInfo);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        try
        {
            byte[] nonce = new byte[GcmNonceSize];
            Buffer.BlockCopy(encryptedBlob, offset, nonce, 0, GcmNonceSize);
            offset += GcmNonceSize;

            byte[] tag = new byte[GcmTagSize];
            Buffer.BlockCopy(encryptedBlob, offset, tag, 0, GcmTagSize);
            offset += GcmTagSize;

            int ciphertextLength = encryptedBlob.Length - offset;
            byte[] ciphertext = new byte[ciphertextLength];
            Buffer.BlockCopy(encryptedBlob, offset, ciphertext, 0, ciphertextLength);

            byte[] plaintext = new byte[ciphertextLength];
            using (var aesGcm = new AesGcm(aesKey, GcmTagSize))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: rawEphemeralKey);
            }

            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }
}
