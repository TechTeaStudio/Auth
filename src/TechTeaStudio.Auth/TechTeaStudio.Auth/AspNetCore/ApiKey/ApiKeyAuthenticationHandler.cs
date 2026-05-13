using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;

namespace TechTeaStudio.Auth.AspNetCore.ApiKey;

/// <summary>
/// AuthenticationHandler that resolves <see cref="ApiKeyAuthenticationOptions.HeaderName"/>
/// (and, optionally, <c>Authorization: ApiKey &lt;key&gt;</c>) against an
/// <see cref="IApiKeyStore"/>. Failure produces <see cref="AuthenticateResult.NoResult"/>
/// so chained schemes can have a shot at the request.
/// </summary>
public sealed class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    public const string SchemeName = "TechTeaStudio.ApiKey";
    private readonly IApiKeyStore _store;

#if NET8_0_OR_GREATER
    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IApiKeyStore store) : base(options, logger, encoder)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }
#else
    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<ApiKeyAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IApiKeyStore store) : base(options, logger, encoder, clock)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }
#endif

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var raw = ExtractKey();
        if (string.IsNullOrEmpty(raw)) return AuthenticateResult.NoResult();

        var result = await _store.ValidateAsync(raw!, Context.RequestAborted).ConfigureAwait(false);
        if (!result.IsValid || string.IsNullOrEmpty(result.SubjectId))
            return AuthenticateResult.Fail("Invalid API key.");

        var claims = new List<Claim>(result.Claims ?? Array.Empty<Claim>())
        {
            new(AuthClaims.Subject, result.SubjectId!),
        };
        var identity = new ClaimsIdentity(claims, Scheme.Name, AuthClaims.Username, AuthClaims.Role);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    private string? ExtractKey()
    {
        if (Context.Request.Headers.TryGetValue(Options.HeaderName, out var v) && !string.IsNullOrEmpty(v))
            return v.ToString();

        if (Options.AllowAuthorizationHeader
            && Context.Request.Headers.TryGetValue("Authorization", out var authHeader)
            && !string.IsNullOrEmpty(authHeader))
        {
            var s = authHeader.ToString();
            if (s.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
                return s.Substring("ApiKey ".Length).Trim();
        }
        return null;
    }
}

public static class ApiKeyAuthenticationExtensions
{
    /// <summary>
    /// Adds the API-key scheme. The consumer **must** also register an
    /// <see cref="IApiKeyStore"/> in DI.
    /// </summary>
    public static AuthenticationBuilder AddTechTeaStudioApiKey(
        this AuthenticationBuilder builder,
        Action<ApiKeyAuthenticationOptions>? configure = null) =>
            builder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
                ApiKeyAuthenticationHandler.SchemeName, configure);
}
