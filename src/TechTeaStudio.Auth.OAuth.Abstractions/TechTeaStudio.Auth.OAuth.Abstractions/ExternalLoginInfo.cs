namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Normalized profile returned by <see cref="IExternalAuthProvider.ValidateAsync"/>.
/// Provider-specific differences (Google ID-token JWT vs GitHub access-token + API call)
/// disappear here — the orchestrator (<see cref="ExternalLoginService"/>) sees the same
/// shape for every provider.
/// </summary>
public sealed record ExternalLoginInfo(
    string Provider,
    string ProviderUserId,
    string? Email,
    bool   EmailVerified,
    string? DisplayName,
    string? AvatarUrl,
    IReadOnlyDictionary<string, string>? Extra = null);
