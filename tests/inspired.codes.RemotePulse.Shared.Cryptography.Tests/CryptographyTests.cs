using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Xunit;

namespace InspiredCodes.RemotePulse.Shared.Cryptography.Tests;

public class CryptographyTests : IDisposable
{
    private readonly string _tempKeyPath;

    public CryptographyTests()
    {
        // Generate a unique path inside the workspace's temp area or system temp
        _tempKeyPath = Path.Combine(Path.GetTempPath(), $"remotepulse_test_key_{Guid.NewGuid():N}.dat");
    }

    [Fact]
    public void KeyPairManager_GenerateAndSave_ShouldCreateFile()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);

        // Act
        Assert.False(manager.KeysExist());
        manager.GenerateAndSaveKeys();

        // Assert
        Assert.True(manager.KeysExist());
        Assert.True(File.Exists(_tempKeyPath));
        Assert.NotEmpty(manager.GetPublicKeyBase64());
    }

    [Fact]
    public void KeyPairManager_GenerateAndSave_ShouldRestrictFilePermissionsToOwnerOnly()
    {
        // DPAPI is gone: owner-only file permissions
        // are now the only protection for the private key, on every platform.
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();

        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            AssertWindowsFileIsRestrictedToCurrentIdentity(_tempKeyPath);
        }
        else
        {
            UnixFileMode mode = File.GetUnixFileMode(_tempKeyPath);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void AssertWindowsFileIsRestrictedToCurrentIdentity(string path)
    {
        var security = new FileInfo(path).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected, "Expected inherited (broader) ACL rules to be disabled.");

        var rules = security.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));
        var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;
        Assert.NotNull(currentUser);
        bool currentUserHasFullControl = rules.Cast<FileSystemAccessRule>().Any(r =>
            r.IdentityReference.Equals(currentUser) &&
            r.AccessControlType == AccessControlType.Allow &&
            (r.FileSystemRights & FileSystemRights.FullControl) == FileSystemRights.FullControl);
        Assert.True(currentUserHasFullControl, "Expected the running identity to have explicit FullControl.");
    }

    [Fact]
    public void KeyPairManager_SignAndVerify_ShouldBeSuccessful()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();

        byte[] originalData = Encoding.UTF8.GetBytes("RemotePulse Security Test Payload");

        // Act
        byte[] signature = manager.SignData(originalData);
        bool isValid = manager.VerifyData(originalData, signature);

        // Assert
        Assert.True(isValid);
        Assert.NotEmpty(signature);
    }

    [Fact]
    public void KeyPairManager_LoadSavedKeys_ShouldDecryptAndSignCorrectly()
    {
        // Arrange
        {
            using KeyPairManager creator = new KeyPairManager(_tempKeyPath);
            creator.GenerateAndSaveKeys();
        }

        // Act
        using KeyPairManager loader = new KeyPairManager(_tempKeyPath);
        loader.LoadKeys();
        byte[] originalData = Encoding.UTF8.GetBytes("Verification after key load");
        byte[] signature = loader.SignData(originalData);
        bool isValid = loader.VerifyData(originalData, signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void KeyPairManager_CorruptKeyFile_ShouldThrowInsteadOfSilentlyRegenerating()
    {
        // BUG-3 regression: a corrupt/unreadable key file must fail loudly. This MachineId/AppId
        // is already registered on the Hub against the old key, so silently minting a new one
        // here would look like unexplained pairing loss with no diagnostic trail.
        File.WriteAllBytes(_tempKeyPath, new byte[] { 0x00, 0x01, 0x02, 0x03 });

        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => manager.SignData(Encoding.UTF8.GetBytes("data")));
        // The corrupt bytes on disk must be left untouched - no silent regeneration occurred.
        Assert.Equal(new byte[] { 0x00, 0x01, 0x02, 0x03 }, File.ReadAllBytes(_tempKeyPath));
    }

    [Fact]
    public void HybridCrypto_EncryptAndDecrypt_SmallPayload_ShouldSucceed()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();
        string publicKeyBase64 = manager.GetPublicKeyBase64();
        byte[] originalData = Encoding.UTF8.GetBytes("Small secret payload");

        // Act
        byte[] encryptedBlob = HybridCrypto.Encrypt(originalData, publicKeyBase64);
        byte[] decryptedData = manager.HybridDecryptData(encryptedBlob);

        // Assert
        Assert.Equal(originalData, decryptedData);
    }

    [Fact]
    public void HybridCrypto_EncryptAndDecrypt_LargePayload_ShouldSucceed()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();
        string publicKeyBase64 = manager.GetPublicKeyBase64();
        
        // Generate > 1KB payload
        byte[] originalData = new byte[2048];
        new Random(42).NextBytes(originalData);

        // Act
        byte[] encryptedBlob = HybridCrypto.Encrypt(originalData, publicKeyBase64);
        byte[] decryptedData = manager.HybridDecryptData(encryptedBlob);

        // Assert
        Assert.Equal(originalData, decryptedData);
    }

    [Fact]
    public void HybridCrypto_Decrypt_TamperedCiphertext_ShouldThrow()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();
        byte[] encryptedBlob = HybridCrypto.Encrypt(Encoding.UTF8.GetBytes("Payload"), manager.GetPublicKeyBase64());

        // Tamper with the last byte (ciphertext)
        encryptedBlob[^1] ^= 0x01;

        // Act & Assert
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => manager.HybridDecryptData(encryptedBlob));
    }

    [Fact]
    public void HybridCrypto_Decrypt_TamperedGcmTag_ShouldThrow()
    {
        // Arrange
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();
        byte[] encryptedBlob = HybridCrypto.Encrypt(Encoding.UTF8.GetBytes("Payload"), manager.GetPublicKeyBase64());

        // Tamper with the GCM tag (which is 16 bytes, located right before the ciphertext)
        // 65 (Ephemeral pub) + 12 (Nonce) = 77
        encryptedBlob[77] ^= 0x01;

        // Act & Assert
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => manager.HybridDecryptData(encryptedBlob));
    }

    [Fact]
    public void HybridCrypto_Decrypt_TamperedEphemeralKey_ShouldThrow()
    {
        // Arrange (SEC-9: rawEphemeralKey is bound into AEAD associatedData)
        using KeyPairManager manager = new KeyPairManager(_tempKeyPath);
        manager.GenerateAndSaveKeys();
        byte[] encryptedBlob = HybridCrypto.Encrypt(Encoding.UTF8.GetBytes("Payload"), manager.GetPublicKeyBase64());

        // Tamper with the ephemeral public key point coordinates (first 65 bytes)
        encryptedBlob[15] ^= 0x01;

        // Act & Assert
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => manager.HybridDecryptData(encryptedBlob));
    }

    public void Dispose()
    {
        try
        {
            if (File.Exists(_tempKeyPath))
            {
                File.Delete(_tempKeyPath);
            }
        }
        catch
        {
            // Ignore clean up errors
        }
    }
}
