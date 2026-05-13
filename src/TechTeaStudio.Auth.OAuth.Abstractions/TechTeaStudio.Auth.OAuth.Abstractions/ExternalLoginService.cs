using System.Security.Claims;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.Observability;
using TechTeaStudio.Auth.Profiles;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Revocation;
using TechTeaStudio.Auth.Tokens;

namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Orchestrates the three-outcome OAuth sign-in flow on top of an
/// <see cref="IExternalAuthProvider"/> (one per provider), the consumer's
/// <see cref="IExternalUserBridge"/>, and the base library's
/// <see cref="RefreshTokenService"/> / <see cref="SignedTokenService"/>.
/// </summary>
public sealed class ExternalLoginService
{
    internal const string LinkPurpose     = "tts.oauth.link";
    internal const string RegisterPurpose = "tts.oauth.register";

    private readonly IReadOnlyDictionary<string, IExternalAuthProvider> _providers;
    private readonly IExternalLoginStore _store;
    private readonly IExternalUserBridge _users;
    private readonly RefreshTokenService _refresh;
    private readonly SignedTokenService _signedTokens;
    private readonly IPasswordHasher _passwords;
    private readonly IClaimsProfile? _claims;
    private readonly IAuthAuditLogger _audit;

    public ExternalLoginService(
        IEnumerable<IExternalAuthProvider> providers,
        IExternalLoginStore store,
        IExternalUserBridge users,
        RefreshTokenService refresh,
        IOptions<AuthOptions> options,
        IPasswordHasher passwords,
        IRevokedTokenStore revoked,
        IClaimsProfile? claims = null,
        IAuthAuditLogger? audit = null)
    {
        if (providers is null) throw new ArgumentNullException(nameof(providers));
        _providers = providers.ToDictionary(p => p.Name, p => p, StringComparer.Ordinal);
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _users = users ?? throw new ArgumentNullException(nameof(users));
        _refresh = refresh ?? throw new ArgumentNullException(nameof(refresh));
        _passwords = passwords ?? throw new ArgumentNullException(nameof(passwords));
        _claims = claims;
        _audit = audit ?? NullAuthAuditLogger.Instance;
        _signedTokens = new SignedTokenService(options, revoked);
    }

    /// <summary>
    /// Top-level sign-in entry point. Validates the provider's credential, then
    /// returns one of: <see cref="ExternalSignInStatus.Authenticated"/> (link
    /// already exists), <see cref="ExternalSignInStatus.RequiresPassword"/>
    /// (email matches an existing password account), or
    /// <see cref="ExternalSignInStatus.RequiresRegistration"/> (new user).
    /// </summary>
    public async Task<ExternalSignInOutcome> SignInAsync(string provider, string rawCredential, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(provider)) return ExternalSignInOutcome.Failed("missing_provider");
        if (string.IsNullOrEmpty(rawCredential)) return ExternalSignInOutcome.Failed("missing_credential");
        if (!_providers.TryGetValue(provider, out var p)) return ExternalSignInOutcome.Failed("unknown_provider");

        var info = await p.ValidateAsync(rawCredential, cancellationToken).ConfigureAwait(false);
        if (info is null) return ExternalSignInOutcome.Failed("invalid_credential");

        // 1. Existing link → authenticate directly.
        var existing = await _store.FindAsync(info.Provider, info.ProviderUserId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            var user = await _users.GetByIdAsync(existing.UserId, cancellationToken).ConfigureAwait(false);
            if (user is null) return ExternalSignInOutcome.Failed("orphaned_link");

            var tokens = await IssueTokensAsync(user, cancellationToken).ConfigureAwait(false);
            await _audit.LogAsync(new LoginSucceededEvent(user.UserId, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
            return ExternalSignInOutcome.Authenticated(tokens);
        }

        // 2. Email collision → ask for the existing password and link.
        if (!string.IsNullOrEmpty(info.Email))
        {
            var byEmail = await _users.FindByEmailAsync(info.Email, cancellationToken).ConfigureAwait(false);
            if (byEmail is not null)
            {
                var continuation = _signedTokens.Generate(LinkPurpose, TimeSpan.FromMinutes(10), new Dictionary<string, string>
                {
                    ["uid"]      = byEmail.UserId,
                    ["provider"] = info.Provider,
                    ["psub"]     = info.ProviderUserId,
                    ["email"]    = info.Email,
                });
                return ExternalSignInOutcome.RequiresPassword(continuation, info.Email);
            }
        }

        // 3. Brand-new user → ask for a username and register.
        var extra = new Dictionary<string, string>
        {
            ["provider"]     = info.Provider,
            ["psub"]         = info.ProviderUserId,
            ["email"]        = info.Email ?? string.Empty,
            ["emailVerified"]= info.EmailVerified ? "1" : "0",
            ["name"]         = info.DisplayName ?? string.Empty,
            ["avatar"]       = info.AvatarUrl ?? string.Empty,
        };
        var registration = _signedTokens.Generate(RegisterPurpose, TimeSpan.FromMinutes(10), extra);
        return ExternalSignInOutcome.RequiresRegistration(registration, info);
    }

    /// <summary>
    /// Completes the <see cref="ExternalSignInStatus.RequiresPassword"/> branch:
    /// the user proves ownership of the existing account by typing its password,
    /// and we link the OAuth identity to that account.
    /// </summary>
    public async Task<ExternalSignInOutcome> LinkExistingAccountAsync(string continuationToken, string password, CancellationToken cancellationToken = default)
    {
        var payload = await _signedTokens.ValidateAsync(continuationToken, LinkPurpose, cancellationToken).ConfigureAwait(false);
        if (payload is null) return ExternalSignInOutcome.Failed("invalid_or_expired_continuation");

        if (!payload.TryGetValue("uid", out var userId) || string.IsNullOrEmpty(userId)
         || !payload.TryGetValue("provider", out var provider) || string.IsNullOrEmpty(provider)
         || !payload.TryGetValue("psub", out var psub) || string.IsNullOrEmpty(psub))
            return ExternalSignInOutcome.Failed("malformed_continuation");

        var user = await _users.GetByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        if (user is null) return ExternalSignInOutcome.Failed("user_not_found");

        if (string.IsNullOrEmpty(user.PasswordHash))
            return ExternalSignInOutcome.Failed("account_has_no_password");
        if (!_passwords.Verify(user.PasswordHash, password ?? string.Empty))
            return ExternalSignInOutcome.Failed("invalid_password");

        payload.TryGetValue("email", out var email);
        await _store.CreateAsync(new ExternalLogin
        {
            UserId = userId,
            Provider = provider,
            ProviderUserId = psub,
            Email = email,
        }, cancellationToken).ConfigureAwait(false);

        var tokens = await IssueTokensAsync(user, cancellationToken).ConfigureAwait(false);
        await _audit.LogAsync(new LoginSucceededEvent(user.UserId, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
        return ExternalSignInOutcome.Authenticated(tokens);
    }

    /// <summary>
    /// Completes the <see cref="ExternalSignInStatus.RequiresRegistration"/>
    /// branch: creates a new password-less account in the consumer's user store
    /// and links the OAuth identity.
    /// </summary>
    public async Task<ExternalSignInOutcome> CompleteRegistrationAsync(string continuationToken, string username, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(username)) return ExternalSignInOutcome.Failed("missing_username");

        var payload = await _signedTokens.ValidateAsync(continuationToken, RegisterPurpose, cancellationToken).ConfigureAwait(false);
        if (payload is null) return ExternalSignInOutcome.Failed("invalid_or_expired_continuation");

        if (!payload.TryGetValue("provider", out var provider) || string.IsNullOrEmpty(provider)
         || !payload.TryGetValue("psub", out var psub) || string.IsNullOrEmpty(psub))
            return ExternalSignInOutcome.Failed("malformed_continuation");

        payload.TryGetValue("email", out var email);
        payload.TryGetValue("emailVerified", out var ev);
        payload.TryGetValue("name", out var name);
        payload.TryGetValue("avatar", out var avatar);

        var info = new ExternalLoginInfo(
            Provider:       provider,
            ProviderUserId: psub,
            Email:          string.IsNullOrEmpty(email) ? null : email,
            EmailVerified:  ev == "1",
            DisplayName:    string.IsNullOrEmpty(name) ? null : name,
            AvatarUrl:      string.IsNullOrEmpty(avatar) ? null : avatar);

        var user = await _users.CreateFromExternalAsync(info, username, cancellationToken).ConfigureAwait(false);
        await _store.CreateAsync(new ExternalLogin
        {
            UserId = user.UserId,
            Provider = provider,
            ProviderUserId = psub,
            Email = info.Email,
        }, cancellationToken).ConfigureAwait(false);

        var tokens = await IssueTokensAsync(user, cancellationToken).ConfigureAwait(false);
        await _audit.LogAsync(new LoginSucceededEvent(user.UserId, DateTimeOffset.UtcNow), cancellationToken).ConfigureAwait(false);
        return ExternalSignInOutcome.Authenticated(tokens);
    }

    /// <summary>
    /// Links a provider identity to an **already-authenticated** user. Used for
    /// Settings → "Connect Google" flows. Caller is responsible for verifying
    /// that <paramref name="userId"/> matches the current <c>HttpContext.User</c>.
    /// </summary>
    public async Task<ExternalSignInOutcome> LinkToUserAsync(string provider, string rawCredential, string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userId)) return ExternalSignInOutcome.Failed("missing_user");
        if (!_providers.TryGetValue(provider, out var p)) return ExternalSignInOutcome.Failed("unknown_provider");

        var info = await p.ValidateAsync(rawCredential, cancellationToken).ConfigureAwait(false);
        if (info is null) return ExternalSignInOutcome.Failed("invalid_credential");

        var existing = await _store.FindAsync(info.Provider, info.ProviderUserId, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
            return existing.UserId == userId
                ? ExternalSignInOutcome.Failed("already_linked_to_this_user")
                : ExternalSignInOutcome.Failed("already_linked_to_other_user");

        var user = await _users.GetByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        if (user is null) return ExternalSignInOutcome.Failed("user_not_found");

        await _store.CreateAsync(new ExternalLogin
        {
            UserId = userId,
            Provider = info.Provider,
            ProviderUserId = info.ProviderUserId,
            Email = info.Email,
        }, cancellationToken).ConfigureAwait(false);

        var tokens = await IssueTokensAsync(user, cancellationToken).ConfigureAwait(false);
        return ExternalSignInOutcome.Authenticated(tokens);
    }

    private async Task<RefreshTokens.TokenPair> IssueTokensAsync(ExternalUserSnapshot user, CancellationToken ct)
    {
        var claims = BuildClaims(user);
        return await _refresh.IssueAsync(user.UserId, claims, ct).ConfigureAwait(false);
    }

    private IEnumerable<Claim> BuildClaims(ExternalUserSnapshot user)
    {
        if (_claims is not null)
        {
            return _claims.BuildClaims(new ClaimsBuilderInput
            {
                UserId   = user.UserId,
                Email    = user.Email,
                Username = user.Username,
                Roles    = user.Roles,
            });
        }
        // Default claim set when no IClaimsProfile is registered.
        var list = new List<Claim>();
        if (!string.IsNullOrEmpty(user.Email))    list.Add(new Claim(AuthClaims.Email, user.Email));
        if (!string.IsNullOrEmpty(user.Username)) list.Add(new Claim(AuthClaims.Username, user.Username));
        foreach (var role in user.Roles)
            if (!string.IsNullOrEmpty(role)) list.Add(new Claim(AuthClaims.Role, role));
        return list;
    }
}
