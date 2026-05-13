using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Produces the JSON 401 body returned by <c>OnChallenge</c>. Maps the underlying
/// <see cref="SecurityTokenException"/> to an <see cref="AuthErrorCodes"/> string
/// so consumers can react programmatically (e.g. "token_expired" → refresh).
/// </summary>
internal static class JwtChallengeWriter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static async Task WriteAsync(JwtBearerChallengeContext context)
    {
        // Stop the default behaviour (which writes the WWW-Authenticate header only).
        context.HandleResponse();

        var (code, message) = Classify(context);

        context.Response.StatusCode = StatusCodes401;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Headers["WWW-Authenticate"] = $"Bearer error=\"{code}\"";

        var traceId = context.HttpContext.TraceIdentifier;
        var payload = new
        {
            error = code,
            message,
            traceId,
        };
        await context.Response.WriteAsync(JsonSerializer.Serialize(payload, JsonOpts)).ConfigureAwait(false);
    }

    private const int StatusCodes401 = 401;

    private static (string code, string message) Classify(JwtBearerChallengeContext context)
    {
        var ex = context.AuthenticateFailure;
        return ex switch
        {
            SecurityTokenExpiredException        => (AuthErrorCodes.TokenExpired, "Token has expired."),
            SecurityTokenInvalidSignatureException => (AuthErrorCodes.InvalidSignature, "Token signature is invalid."),
            SecurityTokenInvalidIssuerException  => (AuthErrorCodes.InvalidIssuer, "Token issuer is not trusted."),
            SecurityTokenInvalidAudienceException => (AuthErrorCodes.InvalidAudience, "Token audience is not accepted."),
            SecurityTokenNotYetValidException    => (AuthErrorCodes.TokenNotYetValid, "Token is not yet valid."),
            SecurityTokenMalformedException      => (AuthErrorCodes.MalformedToken, "Token is malformed."),
            SecurityTokenException               => (AuthErrorCodes.Unauthorized, "Token validation failed."),
            null when string.IsNullOrEmpty(context.HttpContext.Request.Headers.Authorization)
                                                 => (AuthErrorCodes.MissingToken, "Authorization header missing."),
            _                                    => (AuthErrorCodes.Unauthorized, "Authentication required."),
        };
    }
}
