using System.Security.Cryptography;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.Passwords;

/// <summary>
/// PBKDF2-SHA256 password hasher. Storage format is a single Base64 string:
/// <c>[version:1][salt:16][digest:32]</c>. The version byte is reserved for future
/// algorithm upgrades — currently <c>0x01</c>.
/// </summary>
public sealed class Pbkdf2PasswordHasher : IPasswordHasher
{
    internal const byte Version1 = 0x01;
    internal const int SaltSize = 16;
    internal const int HashSize = 32;
    internal const int Iterations = 600_000;

    /// <inheritdoc />
    public string Hash(string password)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var digest = Pbkdf2(password, salt, Iterations, HashSize);

        var blob = new byte[1 + SaltSize + HashSize];
        blob[0] = Version1;
        Buffer.BlockCopy(salt, 0, blob, 1, SaltSize);
        Buffer.BlockCopy(digest, 0, blob, 1 + SaltSize, HashSize);
        return Convert.ToBase64String(blob);
    }

    /// <inheritdoc />
    public bool Verify(string hashedPassword, string providedPassword)
    {
        if (string.IsNullOrEmpty(hashedPassword)) return false;
        if (providedPassword is null) return false;

        byte[] blob;
        try
        {
            blob = Convert.FromBase64String(hashedPassword);
        }
        catch (FormatException)
        {
            return false;
        }

        if (blob.Length != 1 + SaltSize + HashSize) return false;
        if (blob[0] != Version1) return false;

        var salt = new byte[SaltSize];
        Buffer.BlockCopy(blob, 1, salt, 0, SaltSize);

        var storedDigest = new byte[HashSize];
        Buffer.BlockCopy(blob, 1 + SaltSize, storedDigest, 0, HashSize);

        var providedDigest = Pbkdf2(providedPassword, salt, Iterations, HashSize);

        return CryptographicOperations.FixedTimeEquals(providedDigest, storedDigest);
    }

    private static byte[] Pbkdf2(string password, byte[] salt, int iterations, int outputLength)
    {
#if NET6_0_OR_GREATER
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, outputLength);
#else
        using var derive = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return derive.GetBytes(outputLength);
#endif
    }
}
