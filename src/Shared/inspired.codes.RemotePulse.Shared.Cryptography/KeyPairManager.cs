using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace InspiredCodes.RemotePulse.Shared.Cryptography;

public sealed class KeyPairManager : IKeyPairManager, IDisposable
{
    private readonly string _keyPath;
    private ECDsa? _ecdsa;
    private ECDiffieHellman? _ecdh;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPairManager"/> class.
    /// </summary>
    /// <param name="keyPath">The absolute path where the encrypted private key is/will be stored.</param>
    public KeyPairManager(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath))
        {
            throw new ArgumentException("Key storage path cannot be null or empty.", nameof(keyPath));
        }
        _keyPath = keyPath;
    }

    /// <inheritdoc/>
    public bool KeysExist()
    {
        return File.Exists(_keyPath);
    }

    /// <inheritdoc/>
    public void GenerateAndSaveKeys()
    {
        _ecdsa?.Dispose();
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] privateKeyBytes = _ecdsa.ExportPkcs8PrivateKey();

        // GetDirectoryName returns "" (not null) for a bare filename, and on a non-Windows
        // host a stray "C:\..."-style path counts as one - passing that "" to CreateDirectory
        // throws ArgumentException, so treat it like "no directory component".
        string? directory = Path.GetDirectoryName(_keyPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        WriteKeyFileWithOwnerOnlyAccess(privateKeyBytes);
        CryptographicOperations.ZeroMemory(privateKeyBytes);

        LoadEcdhFromEcdsa();
    }

    /// <inheritdoc/>
    public void LoadKeys()
    {
        if (!KeysExist())
        {
            throw new FileNotFoundException("Private key file not found.", _keyPath);
        }

        byte[] privateKeyBytes = File.ReadAllBytes(_keyPath);

        _ecdsa?.Dispose();
        _ecdsa = ECDsa.Create();
        try
        {
            _ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyBytes);
        }

        LoadEcdhFromEcdsa();
    }

    /// <summary>
    /// Writes the private key file with access restricted to the identity this process runs
    /// as (SYSTEM on a Windows Service, whatever account runs it on Linux/macOS) - not tied to
    /// any interactive login, since the Windows Service already runs before any user logs on.
    /// This deliberately replaces DPAPI (which has no cross-platform equivalent): the same
    /// mechanism now runs on every OS, at the cost of losing DPAPI's at-rest encryption of the
    /// key bytes themselves - owner-only file permissions are the only remaining barrier. That
    /// trade is acceptable given this system's scope: personal machines, never exposed to the
    /// public internet. Permissions are applied before any key bytes are written,
    /// so the file is never briefly world-readable.
    /// </summary>
    private void WriteKeyFileWithOwnerOnlyAccess(byte[] privateKeyBytes)
    {
        if (File.Exists(_keyPath))
        {
            File.Delete(_keyPath); // Start clean so a stale broader ACL/mode can't linger.
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            using (File.Create(_keyPath)) { } // Create empty first so we can restrict its ACL before writing key bytes.

            FileSecurity security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false); // Drop inherited (broader) rules from the parent directory.
            SecurityIdentifier? currentIdentity = WindowsIdentity.GetCurrent().User;
            if (currentIdentity != null)
            {
                security.AddAccessRule(new FileSystemAccessRule(currentIdentity, FileSystemRights.FullControl, AccessControlType.Allow));
            }
            new FileInfo(_keyPath).SetAccessControl(security);

            File.WriteAllBytes(_keyPath, privateKeyBytes);
        }
        else
        {
            using (File.Create(_keyPath)) { }
            File.SetUnixFileMode(_keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.WriteAllBytes(_keyPath, privateKeyBytes);
        }
    }
    
    private void LoadEcdhFromEcdsa()
    {
        _ecdh?.Dispose();
        _ecdh = ECDiffieHellman.Create();
        var ecParams = _ecdsa!.ExportParameters(true);
        _ecdh.ImportParameters(ecParams);
    }

    /// <inheritdoc/>
    public string GetPublicKeyBase64()
    {
        EnsureKeysLoaded();
        byte[] publicKeyBytes = _ecdsa!.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(publicKeyBytes);
    }

    /// <inheritdoc/>
    public byte[] SignData(byte[] data)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        EnsureKeysLoaded();
        return _ecdsa!.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <inheritdoc/>
    public bool VerifyData(byte[] data, byte[] signature)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (signature == null) throw new ArgumentNullException(nameof(signature));
        EnsureKeysLoaded();
        return _ecdsa!.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private void EnsureKeysLoaded()
    {
        if (_ecdsa == null)
        {
            if (KeysExist())
            {
                // A corrupt/unreadable key file must fail loudly, not silently mint a fresh
                // identity: this MachineId/AppId's registration on the Hub is bound to the old
                // key, so a silent re-key looks like pairing loss with no diagnostic trail.
                // Only the file-does-not-exist path below is allowed to generate a new keypair.
                LoadKeys();
            }
            else
            {
                GenerateAndSaveKeys();
            }
        }
    }

    /// <inheritdoc/>
    public byte[] HybridDecryptData(byte[] encryptedBlob)
    {
        if (encryptedBlob == null) throw new ArgumentNullException(nameof(encryptedBlob));
        EnsureKeysLoaded();
        return HybridCrypto.Decrypt(encryptedBlob, _ecdh!);
    }

    /// <inheritdoc/>
    public ECParameters GetEcParameters()
    {
        EnsureKeysLoaded();
        return _ecdsa!.ExportParameters(false);
    }

    public void Dispose()
    {
        _ecdsa?.Dispose();
        _ecdh?.Dispose();
    }
}
