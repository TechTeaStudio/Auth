using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace TechTeaStudio.Auth.Signing;

/// <summary>
/// Resolves <see cref="SigningKeyDescriptor"/> entries (and the legacy
/// <see cref="AuthOptions.SecretKey"/>) into <see cref="SecurityKey"/> and
/// <see cref="SigningCredentials"/> instances. Centralised here so the JWT
/// provider and the bearer middleware see exactly the same key material.
/// </summary>
public static class SigningKeyResolver
{
    /// <summary>The synthesized kid used when no descriptors are configured and only the legacy SecretKey is in play.</summary>
    public const string LegacyDefaultKid = "default";

    /// <summary>Returns the descriptor chosen for signing new tokens.</summary>
    public static SigningKeyDescriptor ResolveActive(AuthOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        return ResolveActive(options.Jwt);
    }

    /// <summary>Returns the descriptor chosen for signing new tokens.</summary>
    public static SigningKeyDescriptor ResolveActive(JwtOptions jwt)
    {
        if (jwt is null) throw new ArgumentNullException(nameof(jwt));

        // Legacy path: no Signing.Keys configured, synthesize from SecretKey.
        if (jwt.Signing.Keys.Count == 0)
            return new SigningKeyDescriptor
            {
                Kid = LegacyDefaultKid,
                Algorithm = SigningAlgorithm.HS256,
                SymmetricKey = jwt.SecretKey,
                CreatedAt = DateTimeOffset.UtcNow,
            };

        var activeKid = jwt.Signing.ActiveKid;
        if (!string.IsNullOrEmpty(activeKid))
        {
            var match = jwt.Signing.Keys.FirstOrDefault(k =>
                string.Equals(k.Kid, activeKid, StringComparison.Ordinal));
            if (match is not null) return match;
            throw new InvalidOperationException($"Jwt.Signing.ActiveKid '{activeKid}' is not present in Jwt.Signing.Keys.");
        }
        return jwt.Signing.Keys[0];
    }

    /// <summary>Returns every descriptor whose <see cref="SigningKeyDescriptor.CreatedAt"/> is within the retention window.</summary>
    public static IEnumerable<SigningKeyDescriptor> ResolveValidating(AuthOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        return ResolveValidating(options.Jwt);
    }

    /// <summary>Returns every descriptor whose <see cref="SigningKeyDescriptor.CreatedAt"/> is within the retention window.</summary>
    public static IEnumerable<SigningKeyDescriptor> ResolveValidating(JwtOptions jwt)
    {
        if (jwt is null) throw new ArgumentNullException(nameof(jwt));

        if (jwt.Signing.Keys.Count == 0)
        {
            yield return ResolveActive(jwt);
            yield break;
        }

        var active = ResolveActive(jwt);
        yield return active;

        var retention = jwt.Signing.KeyRetention;
        if (retention <= TimeSpan.Zero) yield break;

        var cutoff = DateTimeOffset.UtcNow - retention;
        foreach (var k in jwt.Signing.Keys)
        {
            if (ReferenceEquals(k, active)) continue;
            if (k.CreatedAt >= cutoff) yield return k;
        }
    }

    /// <summary>
    /// Builds <see cref="TokenValidationParameters"/> for the current options
    /// snapshot — shared by <c>JwtTokenProvider</c> and the bearer middleware.
    /// </summary>
    public static TokenValidationParameters BuildValidationParameters(AuthOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));
        var keys = ResolveValidating(options.Jwt).Select(BuildValidationKey).ToList();

        return new TokenValidationParameters
        {
            ValidateIssuer = !string.IsNullOrEmpty(options.Jwt.Issuer),
            ValidIssuer = options.Jwt.Issuer,
            ValidateAudience = !string.IsNullOrEmpty(options.Jwt.Audience),
            ValidAudience = options.Jwt.Audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = keys,
            ClockSkew = options.Jwt.ClockSkew,
            NameClaimType = Abstractions.AuthClaims.Username,
            RoleClaimType = Abstractions.AuthClaims.Role,
        };
    }

    /// <summary>
    /// Returns the HMAC-SHA256 key used for server-only signed tokens (email
    /// confirmation, password reset). Prefers an HS256 entry from
    /// <c>Jwt.Signing.Keys</c>, then the legacy <c>Jwt.SecretKey</c>. Throws if
    /// neither is configured.
    /// </summary>
    public static byte[] ResolveServerHmacKey(AuthOptions options)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));

        var hs = options.Jwt.Signing.Keys
            .FirstOrDefault(k => k.Algorithm == SigningAlgorithm.HS256 && !string.IsNullOrEmpty(k.SymmetricKey));
        if (hs is not null) return Encoding.UTF8.GetBytes(hs.SymmetricKey!);

        if (!string.IsNullOrEmpty(options.Jwt.SecretKey))
            return Encoding.UTF8.GetBytes(options.Jwt.SecretKey);

        throw new InvalidOperationException(
            "Server-signed tokens require either Auth:Jwt:SecretKey or an HS256 entry in Auth:Jwt:Signing:Keys.");
    }

    /// <summary>Builds <see cref="SigningCredentials"/> for signing new tokens.</summary>
    public static SigningCredentials BuildSigningCredentials(SigningKeyDescriptor descriptor)
    {
        var (key, alg) = BuildSecurityKeyForSigning(descriptor);
        return new SigningCredentials(key, alg);
    }

    /// <summary>Builds the <see cref="SecurityKey"/> used for validation. Public key for asymmetric, symmetric for HS256.</summary>
    public static SecurityKey BuildValidationKey(SigningKeyDescriptor descriptor)
    {
        var key = BuildSecurityKey(descriptor, requirePrivate: false);
        key.KeyId = descriptor.Kid;
        return key;
    }

    private static (SecurityKey Key, string Algorithm) BuildSecurityKeyForSigning(SigningKeyDescriptor descriptor)
    {
        var key = BuildSecurityKey(descriptor, requirePrivate: true);
        key.KeyId = descriptor.Kid;
        var alg = descriptor.Algorithm switch
        {
            SigningAlgorithm.HS256 => SecurityAlgorithms.HmacSha256,
            SigningAlgorithm.RS256 => SecurityAlgorithms.RsaSha256,
            SigningAlgorithm.ES256 => SecurityAlgorithms.EcdsaSha256,
            _ => throw new NotSupportedException($"Algorithm {descriptor.Algorithm} is not supported."),
        };
        return (key, alg);
    }

    private static SecurityKey BuildSecurityKey(SigningKeyDescriptor descriptor, bool requirePrivate)
    {
        switch (descriptor.Algorithm)
        {
            case SigningAlgorithm.HS256:
            {
                if (string.IsNullOrEmpty(descriptor.SymmetricKey))
                    throw new InvalidOperationException($"HS256 descriptor (kid='{descriptor.Kid}') is missing SymmetricKey.");
                var bytes = Encoding.UTF8.GetBytes(descriptor.SymmetricKey);
                if (bytes.Length < 32)
                    throw new InvalidOperationException($"HS256 descriptor (kid='{descriptor.Kid}') SymmetricKey must be ≥ 32 UTF-8 bytes.");
                return new SymmetricSecurityKey(bytes);
            }
            case SigningAlgorithm.RS256:
            {
                var rsa = RSA.Create();
                if (!string.IsNullOrEmpty(descriptor.PrivateKeyPem))
                    rsa.ImportFromPem(descriptor.PrivateKeyPem);
                else if (!string.IsNullOrEmpty(descriptor.PublicKeyPem))
                {
                    if (requirePrivate)
                        throw new InvalidOperationException($"RS256 descriptor (kid='{descriptor.Kid}') needs PrivateKeyPem to sign.");
                    rsa.ImportFromPem(descriptor.PublicKeyPem);
                }
                else throw new InvalidOperationException($"RS256 descriptor (kid='{descriptor.Kid}') needs PrivateKeyPem or PublicKeyPem.");
                return new RsaSecurityKey(rsa);
            }
            case SigningAlgorithm.ES256:
            {
                var ec = ECDsa.Create();
                if (!string.IsNullOrEmpty(descriptor.PrivateKeyPem))
                    ec.ImportFromPem(descriptor.PrivateKeyPem);
                else if (!string.IsNullOrEmpty(descriptor.PublicKeyPem))
                {
                    if (requirePrivate)
                        throw new InvalidOperationException($"ES256 descriptor (kid='{descriptor.Kid}') needs PrivateKeyPem to sign.");
                    ec.ImportFromPem(descriptor.PublicKeyPem);
                }
                else throw new InvalidOperationException($"ES256 descriptor (kid='{descriptor.Kid}') needs PrivateKeyPem or PublicKeyPem.");
                return new ECDsaSecurityKey(ec);
            }
            default:
                throw new NotSupportedException($"Algorithm {descriptor.Algorithm} is not supported.");
        }
    }
}
