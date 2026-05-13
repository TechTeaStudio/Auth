using System.Security.Cryptography;
using System.Text;

namespace TechTeaStudio.Auth.TwoFactor;

/// <summary>
/// Generates and verifies one-time recovery codes that users can use when they
/// lose their 2FA device. Codes are drawn from a "friendly" alphabet that omits
/// look-alike characters (0/O, 1/I/L) so users can hand-copy them reliably.
/// </summary>
public static class RecoveryCodeService
{
    /// <summary>Friendly base-32-style alphabet, 32 chars, no look-alikes.</summary>
    public const string Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

    /// <summary>Default code length used by <see cref="Generate"/>.</summary>
    public const int DefaultLength = 8;

    /// <summary>Default number of codes minted per call.</summary>
    public const int DefaultCount = 10;

    /// <summary>Generates <paramref name="count"/> fresh codes of <paramref name="length"/> chars.</summary>
    public static string[] Generate(int count = DefaultCount, int length = DefaultLength)
    {
        if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));

        var codes = new string[count];
        var alphabet = Alphabet;
        for (var i = 0; i < count; i++)
        {
            var buf = new char[length];
            for (var j = 0; j < length; j++)
                buf[j] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
            codes[i] = new string(buf);
        }
        return codes;
    }

    /// <summary>SHA-256 of the upper-case normalized code, hex-encoded lower-case.</summary>
    public static string Hash(string code)
    {
        if (string.IsNullOrEmpty(code)) return string.Empty;
        var bytes = Encoding.UTF8.GetBytes(code.Trim().ToUpperInvariant());
#if NET6_0_OR_GREATER
        Span<byte> digest = stackalloc byte[32];
        SHA256.HashData(bytes, digest);
#else
        using var sha = SHA256.Create();
        var digest = sha.ComputeHash(bytes);
#endif
        var sb = new StringBuilder(64);
        for (var i = 0; i < digest.Length; i++) sb.Append(digest[i].ToString("x2"));
        return sb.ToString();
    }

    /// <summary>
    /// Constant-time match between a presented code and a previously stored hash.
    /// Always returns false for empty input.
    /// </summary>
    public static bool Verify(string presented, string storedHash)
    {
        if (string.IsNullOrEmpty(presented) || string.IsNullOrEmpty(storedHash)) return false;
        var presentedHash = Hash(presented);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(presentedHash),
            Encoding.ASCII.GetBytes(storedHash));
    }
}
