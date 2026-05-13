using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.Signing;

namespace TechTeaStudio.Auth.AspNetCore.Jwks;

/// <summary>
/// Maps a JWKS endpoint (default <c>/.well-known/jwks.json</c>) that exposes the
/// public-key half of every <see cref="SigningKeyDescriptor"/> within retention,
/// minus HS256 entries (symmetric keys must stay secret).
/// </summary>
public static class JwksEndpointExtensions
{
    /// <summary>Default path served by <see cref="MapTechTeaStudioJwks"/>.</summary>
    public const string DefaultPath = "/.well-known/jwks.json";

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>
    /// Adds a JWKS endpoint. Symmetric (HS256) keys are intentionally excluded —
    /// the JWKS document is meant for third-party validators that do not share a secret.
    /// </summary>
    public static IEndpointConventionBuilder MapTechTeaStudioJwks(this IEndpointRouteBuilder endpoints, string path = DefaultPath)
    {
        if (endpoints is null) throw new ArgumentNullException(nameof(endpoints));

        return endpoints.MapGet(path, (HttpContext ctx) =>
        {
            var monitor = ctx.RequestServices.GetRequiredService<IOptionsMonitor<AuthOptions>>();
            var options = monitor.CurrentValue;

            var jwks = SigningKeyResolver.ResolveValidating(options)
                .Where(d => d.Algorithm is SigningAlgorithm.RS256 or SigningAlgorithm.ES256)
                .Select(BuildJwk)
                .Where(j => j is not null)
                .ToArray();

            ctx.Response.ContentType = "application/jwk-set+json; charset=utf-8";
            // JWKS is hit by every third-party validator on every cache-miss. A short
            // cache window saves the RSA/EC PEM import on the hot path and lets CDNs
            // / intermediaries help. 10 minutes still picks up a key rotation quickly.
            ctx.Response.Headers["Cache-Control"] = "public, max-age=600";
            return ctx.Response.WriteAsync(JsonSerializer.Serialize(new { keys = jwks }, Json));
        });
    }

    private static object? BuildJwk(SigningKeyDescriptor d)
    {
        var key = SigningKeyResolver.BuildValidationKey(d);
        return d.Algorithm switch
        {
            SigningAlgorithm.RS256 when key is RsaSecurityKey rsa && rsa.Rsa is not null => RsaJwk(rsa.Rsa, d.Kid),
            SigningAlgorithm.ES256 when key is ECDsaSecurityKey ec => EcdsaJwk(ec.ECDsa, d.Kid),
            _ => null,
        };
    }

    private static object RsaJwk(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "RSA",
            use = "sig",
            alg = "RS256",
            kid,
            n = Base64Url(p.Modulus!),
            e = Base64Url(p.Exponent!),
        };
    }

    private static object EcdsaJwk(ECDsa ec, string kid)
    {
        var p = ec.ExportParameters(includePrivateParameters: false);
        return new
        {
            kty = "EC",
            use = "sig",
            alg = "ES256",
            crv = "P-256",
            kid,
            x = Base64Url(p.Q.X!),
            y = Base64Url(p.Q.Y!),
        };
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
