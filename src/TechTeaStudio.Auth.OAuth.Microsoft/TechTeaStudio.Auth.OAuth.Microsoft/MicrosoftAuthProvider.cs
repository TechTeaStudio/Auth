using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace TechTeaStudio.Auth.OAuth.Microsoft;

/// <summary>
/// Microsoft Entra ID (formerly Azure AD) sign-in, v2.0 endpoints.
///
/// <para>The raw credential is the <b>authorization code</b>, same shape as
/// <c>TechTeaStudio.Auth.OAuth.GitHub</c>: the consumer redirects to
/// <c>{Instance}/{TenantId}/oauth2/v2.0/authorize</c>, Entra bounces back with <c>?code=</c>, and
/// this provider trades that code for an id_token and validates it.</para>
///
/// <para><b>PKCE.</b> <see cref="IExternalAuthProvider.ValidateAsync"/> carries one string, so a
/// host that sent a <c>code_challenge</c> on the authorize request passes the code and its
/// verifier together: build the credential with <see cref="FormatCredential"/>. A bare code keeps
/// working for hosts that do not use PKCE. <c>state</c> and <c>nonce</c> never reach this class -
/// checking them is the host's job, on the callback, before it calls sign-in.</para>
///
/// <para><b>Why the id_token is validated at all</b> when it arrives over TLS in the response to
/// our own client-authenticated request: the signature check is what makes this class safe to
/// reuse for any future flow where the token does NOT come straight from the token endpoint, and
/// it costs one cached JWKS fetch. The parts that actually matter are the audience (the token was
/// minted for THIS application) and the issuer (it came from the tenant we asked for).</para>
/// </summary>
public sealed class MicrosoftAuthProvider : IExternalAuthProvider
{
    public const string ProviderName = "Microsoft";
    public string Name => ProviderName;

    /// <summary>The tenant every personal Microsoft account (outlook.com, live.com, …) lives in.
    /// Its tokens are issued by Microsoft itself, not by a customer-administered directory.</summary>
    private const string ConsumerTenantId = "9188040d-6c67-4c5b-b112-36a304b66dad";

    /// <summary>JWKS per authority, shared across instances because the provider is registered
    /// transient (one per resolve, like the GitHub one) and a per-instance cache would fetch the
    /// key set on every sign-in.</summary>
    private static readonly ConcurrentDictionary<string, CachedKeys> KeyCache = new(StringComparer.Ordinal);

    private readonly HttpClient _http;
    private readonly IOptionsMonitor<MicrosoftAuthProviderOptions> _options;
    private readonly ILogger<MicrosoftAuthProvider>? _logger;

    public MicrosoftAuthProvider(
        HttpClient http,
        IOptionsMonitor<MicrosoftAuthProviderOptions> options,
        ILogger<MicrosoftAuthProvider>? logger = null)
    {
        _http = http;
        _options = options;
        _logger = logger;
    }

    public async Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawCredential)) return null;

        var opts = _options.CurrentValue;
        if (string.IsNullOrWhiteSpace(opts.ClientId) || string.IsNullOrWhiteSpace(opts.ClientSecret))
        {
            _logger?.LogWarning("Microsoft OAuth not configured (missing ClientId/ClientSecret)");
            return null;
        }
        if (string.IsNullOrWhiteSpace(opts.RedirectUri))
        {
            _logger?.LogWarning("Microsoft OAuth not configured (missing RedirectUri - Entra rejects the token exchange without it)");
            return null;
        }

        try
        {
            if (!TryReadCredential(rawCredential, out var code, out var codeVerifier))
            {
                _logger?.LogInformation("Microsoft credential rejected: neither an authorization code nor a code + code_verifier object");
                return null;
            }

            var idToken = await ExchangeCodeAsync(code, codeVerifier, opts, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(idToken)) return null;

            var token = await ValidateIdTokenAsync(idToken!, opts, cancellationToken).ConfigureAwait(false);
            if (token is null) return null;

            var subject = SubjectOf(token);
            if (string.IsNullOrEmpty(subject))
            {
                _logger?.LogWarning("Microsoft id_token carried neither oid nor sub - cannot key an external login on it");
                return null;
            }

            var email = EmailOf(token);
            if (opts.RequireEmail && string.IsNullOrEmpty(email))
            {
                _logger?.LogInformation("Microsoft user {Subject} rejected: no address on the token", subject);
                return null;
            }

            return new ExternalLoginInfo(
                Provider: ProviderName,
                ProviderUserId: subject!,
                Email: email,
                EmailVerified: IsEmailVerified(token, email, opts),
                DisplayName: ClaimOf(token, "name") ?? ClaimOf(token, "preferred_username"),
                // Deliberately null: a photo needs a Graph call with User.Read on the access
                // token, which would make every sign-in pay for an avatar most apps ignore.
                AvatarUrl: null,
                Extra: null);
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Microsoft OAuth validation failed");
            return null;
        }
    }

    /// <summary>Trades the authorization code for the id_token. Returns null on any non-success
    /// answer; the body is logged at debug because it carries Entra's own error code
    /// (<c>invalid_grant</c>, <c>redirect_uri_mismatch</c>, …), which is the only useful clue when
    /// a registration is misconfigured.</summary>
    private async Task<string?> ExchangeCodeAsync(string code, string? codeVerifier, MicrosoftAuthProviderOptions opts, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"{Authority(opts)}/oauth2/v2.0/token");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var form = new List<KeyValuePair<string, string>>
        {
            new KeyValuePair<string, string>("client_id", opts.ClientId!),
            new KeyValuePair<string, string>("client_secret", opts.ClientSecret!),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("redirect_uri", opts.RedirectUri!),
            new KeyValuePair<string, string>("scope", opts.Scope),
        };
        // Entra answers invalid_grant when the authorize request carried a code_challenge and the
        // exchange carries no verifier, so a PKCE host has no way to sign in without this field.
        if (!string.IsNullOrEmpty(codeVerifier))
            form.Add(new KeyValuePair<string, string>("code_verifier", codeVerifier!));
        req.Content = new FormUrlEncodedContent(form);

        using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            _logger?.LogDebug("Microsoft token endpoint answered {Status}: {Body}", (int)resp.StatusCode, body);
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.TryGetProperty("id_token", out var idToken) ? idToken.GetString() : null;
    }

    private async Task<JwtSecurityToken?> ValidateIdTokenAsync(string idToken, MicrosoftAuthProviderOptions opts, CancellationToken ct)
    {
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };

        // One retry on an unknown key id: Entra rolls signing keys without warning, and a cached
        // key set that predates a roll produces exactly this exception and nothing else.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var keys = await GetSigningKeysAsync(opts, forceRefresh: attempt > 0, ct).ConfigureAwait(false);
            if (keys.Count == 0) return null;

            var parameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = keys,
                ValidateAudience = true,
                ValidAudience = opts.ClientId,
                ValidateLifetime = true,
                ClockSkew = opts.ClockSkew,
                ValidateIssuer = true,
                IssuerValidator = (issuer, securityToken, _) => ValidateIssuer(issuer, securityToken, opts),
            };

            try
            {
                handler.ValidateToken(idToken, parameters, out var validated);
                return validated as JwtSecurityToken;
            }
            catch (SecurityTokenSignatureKeyNotFoundException) when (attempt == 0)
            {
                _logger?.LogDebug("Microsoft id_token signed by an unknown key id - refreshing the JWKS and retrying once");
            }
            catch (SecurityTokenException ex)
            {
                _logger?.LogWarning(ex, "Microsoft id_token rejected");
                return null;
            }
        }

        return null;
    }

    /// <summary>Issuer check for the templated <c>common</c> authority, where the issuer is
    /// per-tenant and therefore unknown until the token is open: the expected value is built from
    /// the token's own <c>tid</c>, which is itself covered by the signature. Configuring a tenant
    /// GUID additionally pins that tid, which is what makes a single-tenant app single-tenant.</summary>
    private static string ValidateIssuer(string issuer, SecurityToken securityToken, MicrosoftAuthProviderOptions opts)
    {
        var tid = (securityToken as JwtSecurityToken)?.Claims.FirstOrDefault(c => c.Type == "tid")?.Value;
        if (string.IsNullOrEmpty(tid))
            throw new SecurityTokenInvalidIssuerException("Microsoft id_token carries no tid claim.");

        if (Guid.TryParse(opts.TenantId, out _) && !string.Equals(tid, opts.TenantId, StringComparison.OrdinalIgnoreCase))
            throw new SecurityTokenInvalidIssuerException(
                $"Microsoft id_token came from tenant {tid}, but this application is pinned to {opts.TenantId}.");

        var expected = $"{Instance(opts)}/{tid}/v2.0";
        if (!string.Equals(issuer, expected, StringComparison.Ordinal))
            throw new SecurityTokenInvalidIssuerException(
                $"Microsoft id_token issuer {issuer} does not match the expected {expected}.");

        return issuer;
    }

    private async Task<IReadOnlyCollection<SecurityKey>> GetSigningKeysAsync(
        MicrosoftAuthProviderOptions opts, bool forceRefresh, CancellationToken ct)
    {
        var url = $"{Authority(opts)}/discovery/v2.0/keys";

        KeyCache.TryGetValue(url, out var cached);
        if (!forceRefresh && cached is not null && cached.ExpiresAt > DateTimeOffset.UtcNow)
            return cached.Keys;

        try
        {
            using var resp = await _http.GetAsync(url, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                _logger?.LogWarning("Microsoft JWKS fetch answered {Status}", (int)resp.StatusCode);
                return cached?.Keys ?? Array.Empty<SecurityKey>();
            }

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            var keys = new JsonWebKeySet(json).GetSigningKeys().ToArray();
            KeyCache[url] = new CachedKeys(keys, DateTimeOffset.UtcNow.Add(opts.SigningKeyCacheLifetime));
            return keys;
        }
        catch (Exception ex)
        {
            // A network blip must not invalidate a key set we already hold.
            _logger?.LogWarning(ex, "Microsoft JWKS fetch failed");
            return cached?.Keys ?? Array.Empty<SecurityKey>();
        }
    }

    /// <summary>The stable per-user key. Microsoft's own guidance is <c>oid</c> paired with
    /// <c>tid</c>: <c>oid</c> alone repeats across tenants, and <c>sub</c> is pairwise per
    /// application, so it would change if this app were ever re-registered. <c>sub</c> is the
    /// fallback for the rare token that carries no oid.</summary>
    private static string? SubjectOf(JwtSecurityToken token)
    {
        var oid = ClaimOf(token, "oid");
        var tid = ClaimOf(token, "tid");
        if (!string.IsNullOrEmpty(oid) && !string.IsNullOrEmpty(tid)) return $"{tid}.{oid}";
        return oid ?? ClaimOf(token, "sub");
    }

    /// <summary>Builds the credential for a PKCE sign-in: the authorization code plus the
    /// <c>code_verifier</c> whose challenge went out on the authorize request. Pass the result to
    /// <c>ExternalLoginService.SignInAsync("Microsoft", …)</c> in place of the bare code.</summary>
    public static string FormatCredential(string code, string codeVerifier)
    {
        if (string.IsNullOrEmpty(code)) throw new ArgumentNullException(nameof(code));
        if (string.IsNullOrEmpty(codeVerifier)) throw new ArgumentNullException(nameof(codeVerifier));
        return JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["code"] = code,
            ["code_verifier"] = codeVerifier,
        });
    }

    /// <summary>Accepts both credential shapes: a bare authorization code, or the JSON object
    /// <see cref="FormatCredential"/> produces. An authorization code never starts with a brace,
    /// so the two cannot be confused.</summary>
    private static bool TryReadCredential(string rawCredential, out string code, out string? codeVerifier)
    {
        code = rawCredential.Trim();
        codeVerifier = null;
        if (!code.StartsWith("{", StringComparison.Ordinal)) return true;

        try
        {
            using var doc = JsonDocument.Parse(code);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("code", out var codeElement)
                || codeElement.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(codeElement.GetString()))
                return false;

            code = codeElement.GetString()!;
            if (root.TryGetProperty("code_verifier", out var verifier) && verifier.ValueKind == JsonValueKind.String)
                codeVerifier = verifier.GetString();
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether the address may be trusted as belonging to whoever signed in. Entra has no
    /// <c>email_verified</c> claim, and the <c>email</c> claim of a work or school account is the
    /// directory's <c>mail</c> attribute, which any tenant administrator can set to an address
    /// they do not own. On a multi-tenant authority (<c>common</c> / <c>organizations</c>) that
    /// means anyone with their own tenant can present anyone's address, so reporting it as
    /// verified would hand a host that auto-links by address an account takeover.
    ///
    /// <para>It is verified only when one of these holds: the token carries
    /// <c>xms_edov = true</c> (Entra's "email domain owner verified" optional claim); the
    /// application is pinned to a single tenant GUID, whose administrator the host already
    /// trusts; or the token comes from the consumer tenant, where Microsoft itself issues the
    /// token and confirms the address on sign-up.</para>
    /// </summary>
    private static bool IsEmailVerified(JwtSecurityToken token, string? email, MicrosoftAuthProviderOptions opts)
    {
        if (string.IsNullOrEmpty(email)) return false;

        var edov = ClaimOf(token, "xms_edov");
        if (string.Equals(edov, "true", StringComparison.OrdinalIgnoreCase) || edov == "1") return true;

        // The issuer check has already rejected any token whose tid differs from a pinned GUID.
        if (Guid.TryParse(opts.TenantId, out _)) return true;

        return string.Equals(ClaimOf(token, "tid"), ConsumerTenantId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The address. Work and school tenants often omit <c>email</c> and carry the UPN in
    /// <c>preferred_username</c> instead; that is only usable when it is shaped like an address,
    /// since the same claim can hold a bare sign-in name.</summary>
    private static string? EmailOf(JwtSecurityToken token)
    {
        var email = ClaimOf(token, "email");
        if (!string.IsNullOrEmpty(email)) return email;

        var upn = ClaimOf(token, "preferred_username");
        return upn is not null && upn.Contains('@') ? upn : null;
    }

    private static string? ClaimOf(JwtSecurityToken token, string type) =>
        token.Claims.FirstOrDefault(c => c.Type == type)?.Value is { Length: > 0 } value ? value : null;

    private static string Instance(MicrosoftAuthProviderOptions opts) =>
        (string.IsNullOrWhiteSpace(opts.Instance) ? "https://login.microsoftonline.com" : opts.Instance).TrimEnd('/');

    private static string Authority(MicrosoftAuthProviderOptions opts) =>
        $"{Instance(opts)}/{(string.IsNullOrWhiteSpace(opts.TenantId) ? "common" : opts.TenantId)}";

    private sealed record CachedKeys(IReadOnlyCollection<SecurityKey> Keys, DateTimeOffset ExpiresAt);
}
