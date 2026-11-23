using System;
using System.Security.Cryptography;

namespace InspiredCodes.RemotePulse.Shared.Cryptography;

public interface IKeyPairManager
{
    /// <summary>
    /// Generates a new NIST P-256 key pair and saves the private key locally, readable only by the owning account.
    /// </summary>
    void GenerateAndSaveKeys();

    /// <summary>
    /// Checks if a saved private key exists locally.
    /// </summary>
    bool KeysExist();

    /// <summary>
    /// Loads the locally stored private key.
    /// </summary>
    void LoadKeys();

    /// <summary>
    /// Gets the base64-encoded Public Key in SubjectPublicKeyInfo format.
    /// </summary>
    string GetPublicKeyBase64();

    /// <summary>
    /// Signs the input data using the loaded private key with ECDSA P-256 (SHA-256).
    /// </summary>
    byte[] SignData(byte[] data);

    /// <summary>
    /// Verifies the signature of the data using the public key with ECDSA P-256 (SHA-256).
    /// </summary>
    bool VerifyData(byte[] data, byte[] signature);

    /// <summary>
    /// Decrypts a hybrid-encrypted blob (AES-256-GCM + ECDH key agreement)
    /// using the loaded private key. Supports payloads of arbitrary length.
    /// </summary>
    byte[] HybridDecryptData(byte[] encryptedBlob);

    /// <summary>
    /// Exposes the internal EC parameters for advanced operations (e.g., HybridCrypto).
    /// </summary>
    ECParameters GetEcParameters();
}
