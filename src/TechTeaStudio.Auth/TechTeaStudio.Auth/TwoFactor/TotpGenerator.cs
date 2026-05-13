using System.Buffers.Binary;
using System.Security.Cryptography;

namespace TechTeaStudio.Auth.TwoFactor;

/// <summary>
/// RFC 6238 TOTP generator. Pure functions — no I/O, no DI. Default values
/// (30-second period, 6-digit codes, HMAC-SHA1) match Google Authenticator /
/// Microsoft Authenticator / Authy.
/// </summary>
public static class TotpGenerator
{
    public const int DefaultDigits = 6;
    public const int DefaultPeriodSeconds = 30;

    /// <summary>Generates the TOTP code for <paramref name="secret"/> at <paramref name="timestamp"/>.</summary>
    public static string Generate(byte[] secret, DateTimeOffset timestamp, int digits = DefaultDigits, int periodSeconds = DefaultPeriodSeconds)
    {
        if (secret is null || secret.Length == 0) throw new ArgumentException("secret required", nameof(secret));
        if (digits is < 6 or > 9) throw new ArgumentOutOfRangeException(nameof(digits));
        if (periodSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(periodSeconds));

        var counter = timestamp.ToUnixTimeSeconds() / periodSeconds;
        return GenerateForCounter(secret, counter, digits);
    }

    internal static string GenerateForCounter(byte[] secret, long counter, int digits)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);

#if NET6_0_OR_GREATER
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(secret, counterBytes, hash);
#else
        using var hmac = new HMACSHA1(secret);
        var hash = hmac.ComputeHash(counterBytes.ToArray());
#endif

        var offset = hash[19] & 0x0F;
        var binCode = ((hash[offset] & 0x7F) << 24)
                    | (hash[offset + 1] << 16)
                    | (hash[offset + 2] << 8)
                    | hash[offset + 3];

        var mod = (int)Math.Pow(10, digits);
        var code = binCode % mod;
        return code.ToString().PadLeft(digits, '0');
    }
}

/// <summary>Validator for RFC 6238 TOTP codes with a configurable tolerance window.</summary>
public static class TotpValidator
{
    /// <summary>
    /// Returns <c>true</c> when <paramref name="code"/> matches the TOTP value computed
    /// for <paramref name="secret"/> at <paramref name="timestamp"/> within
    /// <paramref name="allowedSkew"/> steps in each direction (default ±1 period).
    /// Comparison runs in constant time.
    /// </summary>
    public static bool Validate(byte[] secret, string code, DateTimeOffset timestamp, int allowedSkew = 1, int digits = TotpGenerator.DefaultDigits, int periodSeconds = TotpGenerator.DefaultPeriodSeconds)
    {
        if (secret is null || secret.Length == 0) return false;
        if (string.IsNullOrEmpty(code) || code.Length != digits) return false;
        if (allowedSkew < 0) throw new ArgumentOutOfRangeException(nameof(allowedSkew));

        var baseCounter = timestamp.ToUnixTimeSeconds() / periodSeconds;
        var matched = false;
        for (var i = -allowedSkew; i <= allowedSkew; i++)
        {
            var candidate = TotpGenerator.GenerateForCounter(secret, baseCounter + i, digits);
            // Compare every candidate to avoid early-exit timing differences.
            matched |= CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(candidate),
                System.Text.Encoding.ASCII.GetBytes(code));
        }
        return matched;
    }
}
