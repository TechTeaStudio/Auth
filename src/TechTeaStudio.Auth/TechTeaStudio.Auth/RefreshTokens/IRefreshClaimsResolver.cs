using System.Security.Claims;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Resolves the claim set that should be embedded in the **new** access token
/// when <see cref="RefreshTokenService.RotateAsync(string, System.Threading.CancellationToken)"/>
/// is called without an explicit claims list. Consumer-implemented.
/// </summary>
public interface IRefreshClaimsResolver
{
    /// <summary>Returns the claims to embed in the access token issued for <paramref name="userId"/>.</summary>
    Task<IEnumerable<Claim>> ResolveClaimsAsync(string userId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Default no-op resolver: returns an empty claim list, so the access token
/// carries only <c>sub</c>, <c>jti</c>, <c>iat</c>. Consumers wanting richer
/// claims register their own via <c>builder.UseRefreshClaimsResolver&lt;TResolver&gt;()</c>.
/// </summary>
public sealed class NullRefreshClaimsResolver : IRefreshClaimsResolver
{
    public static NullRefreshClaimsResolver Instance { get; } = new();
    public Task<IEnumerable<Claim>> ResolveClaimsAsync(string userId, CancellationToken cancellationToken = default)
        => Task.FromResult<IEnumerable<Claim>>(Array.Empty<Claim>());
}
