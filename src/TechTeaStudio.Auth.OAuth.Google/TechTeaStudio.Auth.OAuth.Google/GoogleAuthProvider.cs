using global::Google.Apis.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.OAuth.Google;

/// <summary>
/// <see cref="IExternalAuthProvider"/> for Google Sign-In. Accepts a Google ID
/// token (JWT issued by Google to the user's device), validates the signature
/// against Google's JWKS, checks the audience against the configured client IDs,
/// and normalizes the payload into <see cref="ExternalLoginInfo"/>.
/// </summary>
public sealed class GoogleAuthProvider : IExternalAuthProvider
{
    /// <summary>Stable provider name. Use in <c>POST /api/auth/oauth/Google</c>.</summary>
    public const string ProviderName = "Google";

    private readonly IOptionsMonitor<GoogleAuthProviderOptions> _options;
    private readonly ILogger<GoogleAuthProvider>? _logger;

    public GoogleAuthProvider(IOptionsMonitor<GoogleAuthProviderOptions> options, ILogger<GoogleAuthProvider>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;
    }

    /// <inheritdoc />
    public string Name => ProviderName;

    /// <inheritdoc />
    public async Task<ExternalLoginInfo?> ValidateAsync(string rawCredential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(rawCredential)) return null;
        var opts = _options.CurrentValue;
        if (opts.Audiences is null || opts.Audiences.Count == 0)
        {
            _logger?.LogError("GoogleAuthProvider has no Audiences configured — refusing to validate. Set Auth:Google:Audiences in configuration.");
            return null;
        }

        GoogleJsonWebSignature.Payload payload;
        try
        {
            payload = await GoogleJsonWebSignature.ValidateAsync(rawCredential, new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = opts.Audiences,
            }).ConfigureAwait(false);
        }
        catch (InvalidJwtException ex)
        {
            _logger?.LogInformation(ex, "Rejected Google ID token: {Reason}", ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogWarning(ex, "Google ID-token validation crashed.");
            return null;
        }

        if (opts.RequireEmailVerified && !payload.EmailVerified)
            return null;

        return new ExternalLoginInfo(
            Provider:       ProviderName,
            ProviderUserId: payload.Subject,
            Email:          payload.Email,
            EmailVerified:  payload.EmailVerified,
            DisplayName:    payload.Name,
            AvatarUrl:      payload.Picture);
    }
}
