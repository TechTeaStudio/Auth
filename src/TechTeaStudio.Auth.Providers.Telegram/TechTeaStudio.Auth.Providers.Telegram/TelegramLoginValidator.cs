using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TechTeaStudio.Auth.Providers.Telegram;

/// <summary>Why a payload was refused. Surfaced separately from the boolean so a host can log the
/// cause without logging the payload itself.</summary>
public enum TelegramLoginFailure
{
    None = 0,
    Malformed,
    MissingHash,
    MissingAuthDate,
    BadSignature,
    Expired,
}

/// <summary>
/// Validates a Telegram Login Widget payload. Pure function over the payload and the bot token:
/// nothing here talks to Telegram, because Telegram's scheme has no callback to make - the widget
/// hands the browser a profile plus an HMAC, and the bot token is the shared secret that proves it.
///
/// <para><b>The algorithm</b> (from Telegram's "Login Widget" documentation): take every field
/// except <c>hash</c>, sort the keys, join them as <c>key=value</c> with a newline between, and
/// compare the HMAC-SHA256 of that string under the key <c>SHA256(bot_token)</c> against
/// <c>hash</c>. Note the double role of SHA256: the KEY is the digest of the token, not the token.
/// </para>
///
/// <para><b>Freshness is not optional.</b> The payload is a bearer credential with no nonce and no
/// single-use marker, so a captured one replays forever unless <c>auth_date</c> is checked. That is
/// what <c>maxAge</c> is for, and why it defaults to minutes rather than hours.</para>
/// </summary>
public static class TelegramLoginValidator
{
    /// <summary>
    /// Parses and verifies a widget payload.
    /// </summary>
    /// <param name="rawPayload">Either the widget's query string (<c>id=1&amp;auth_date=…&amp;hash=…</c>,
    /// percent-encoded) or the JSON object the <c>data-onauth</c> callback receives. Both shapes
    /// appear in the wild depending on how the host mounted the widget.</param>
    /// <param name="botToken">The bot token from BotFather, exactly as issued.</param>
    /// <param name="maxAge">How old <c>auth_date</c> may be. <see cref="TimeSpan.Zero"/> disables
    /// the check - only sane in tests. A negative value is refused as
    /// <see cref="TelegramLoginFailure.Expired"/>: it can only be a misconfiguration, and reading
    /// it as "no limit" would switch the replay defence off.</param>
    /// <param name="now">Current time, injected so the freshness check is testable.</param>
    /// <param name="fields">Every field of the payload, hash included, on success.</param>
    /// <param name="failure">Why it was refused, on failure.</param>
    public static bool TryValidate(
        string? rawPayload,
        string? botToken,
        TimeSpan maxAge,
        DateTimeOffset now,
        out IReadOnlyDictionary<string, string> fields,
        out TelegramLoginFailure failure)
    {
        fields = new Dictionary<string, string>(StringComparer.Ordinal);

        if (string.IsNullOrWhiteSpace(rawPayload) || string.IsNullOrWhiteSpace(botToken))
        {
            failure = TelegramLoginFailure.Malformed;
            return false;
        }

        var parsed = Parse(rawPayload!);
        if (parsed is null || parsed.Count == 0)
        {
            failure = TelegramLoginFailure.Malformed;
            return false;
        }

        if (!parsed.TryGetValue("hash", out var hash) || string.IsNullOrWhiteSpace(hash))
        {
            failure = TelegramLoginFailure.MissingHash;
            return false;
        }

        if (!parsed.TryGetValue("auth_date", out var authDateRaw)
            || !long.TryParse(authDateRaw, NumberStyles.None, CultureInfo.InvariantCulture, out var authDateUnix))
        {
            failure = TelegramLoginFailure.MissingAuthDate;
            return false;
        }

        // The check string joins fields with a newline, so a newline INSIDE a key or value would
        // let one signed field be re-read as two: first_name "A", newline, "id=1" hashes the same
        // as first_name=A plus id=1. Telegram never emits one; refuse instead of guessing.
        if (parsed.Any(kv => kv.Key.IndexOf('\n') >= 0 || kv.Value.IndexOf('\n') >= 0))
        {
            failure = TelegramLoginFailure.Malformed;
            return false;
        }

        var expected = Sign(parsed, botToken!);
        if (!FixedTimeEqualsHex(expected, hash))
        {
            failure = TelegramLoginFailure.BadSignature;
            return false;
        }

        if (maxAge < TimeSpan.Zero)
        {
            failure = TelegramLoginFailure.Expired;
            return false;
        }

        if (maxAge > TimeSpan.Zero)
        {
            // Past DateTimeOffset's own range: not a date Telegram could have signed.
            if (authDateUnix > 253402300799L)
            {
                failure = TelegramLoginFailure.Expired;
                return false;
            }
            var authDate = DateTimeOffset.FromUnixTimeSeconds(authDateUnix);
            // Both directions: a payload from the future is as suspect as a stale one, and small
            // clock drift on either side is what the caller's maxAge already absorbs.
            var age = now - authDate;
            if (age > maxAge || age < -maxAge)
            {
                failure = TelegramLoginFailure.Expired;
                return false;
            }
        }

        fields = parsed;
        failure = TelegramLoginFailure.None;
        return true;
    }

    /// <summary>The HMAC Telegram would have produced for these fields, lowercase hex.</summary>
    public static string Sign(IReadOnlyDictionary<string, string> fields, string botToken)
    {
        if (fields is null) throw new ArgumentNullException(nameof(fields));
        if (string.IsNullOrEmpty(botToken)) throw new ArgumentNullException(nameof(botToken));

        var checkString = string.Join("\n", fields
            .Where(kv => !string.Equals(kv.Key, "hash", StringComparison.Ordinal))
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => $"{kv.Key}={kv.Value}"));

        var secret = SHA256.HashData(Encoding.UTF8.GetBytes(botToken));
        var mac = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(checkString));
        return ToHex(mac);
    }

    private static Dictionary<string, string>? Parse(string raw)
    {
        var trimmed = raw.Trim();
        return trimmed.StartsWith("{", StringComparison.Ordinal)
            ? ParseJson(trimmed)
            : ParseQueryString(trimmed);
    }

    private static Dictionary<string, string>? ParseJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;

            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                // Telegram sends flat scalars only. Anything nested is not a widget payload, and
                // silently flattening it would change the check string.
                var value = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString(),
                    JsonValueKind.Number => property.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    JsonValueKind.Null => null,
                    _ => null,
                };
                if (value is not null) result[property.Name] = value;
            }
            return result;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var split = pair.IndexOf('=');
            if (split <= 0) continue;
            var key = Uri.UnescapeDataString(pair.Substring(0, split).Replace('+', ' '));
            var value = Uri.UnescapeDataString(pair.Substring(split + 1).Replace('+', ' '));
            result[key] = value;
        }
        return result;
    }

    /// <summary>Constant-time comparison of two hex digests. A plain string compare here would
    /// leak the correct prefix length through timing, which is enough to forge a hash byte by
    /// byte given enough attempts.</summary>
    private static bool FixedTimeEqualsHex(string expected, string actual)
    {
        try
        {
            var a = Convert.FromHexString(expected);
            var b = Convert.FromHexString(actual.Trim());
            return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string ToHex(byte[] bytes)
    {
#if NET6_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
#endif
    }
}
