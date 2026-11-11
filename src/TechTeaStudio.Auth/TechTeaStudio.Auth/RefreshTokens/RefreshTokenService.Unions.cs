#if NET11_0_OR_GREATER
using System.Security.Claims;

namespace TechTeaStudio.Auth.RefreshTokens;

public sealed partial class RefreshTokenService
{
    /// <summary>
    /// Union-returning form of <see cref="RotateWithOutcomeAsync(string, CancellationToken)"/>:
    /// asks the registered <see cref="IRefreshClaimsResolver"/> for the claim set to embed in the
    /// new access token and reports the result as a <see cref="RefreshRotation"/>. <c>net11.0</c> only.
    /// </summary>
    /// <remarks>
    /// Calls <see cref="RotateWithOutcomeAsync(string, CancellationToken)"/> and converts its
    /// result; rotation, reuse detection and family revocation are exactly those of that method.
    /// </remarks>
    public async Task<RefreshRotation> RotateAsUnionAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
    {
        var result = await RotateWithOutcomeAsync(presentedRefreshToken, cancellationToken).ConfigureAwait(false);
        return RefreshRotationMapper.ToUnion(result);
    }

    /// <summary>
    /// Union-returning form of <see cref="RotateWithOutcomeAsync(string, IEnumerable{Claim}, CancellationToken)"/>:
    /// rotates the presented refresh token, embedding <paramref name="claims"/> into the new
    /// access token, and reports the result as a <see cref="RefreshRotation"/> so a
    /// <c>switch</c> over it is checked for exhaustiveness. <c>net11.0</c> only.
    /// </summary>
    /// <remarks>
    /// Calls <see cref="RotateWithOutcomeAsync(string, IEnumerable{Claim}, CancellationToken)"/>
    /// and converts its result; see that method for the race-handling rules. A lost
    /// compare-and-swap race is <see cref="RefreshTokenInvalid"/>, a replay is
    /// <see cref="RefreshTokenReused"/>.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="claims"/> is <c>null</c> and the token is not empty.</exception>
    public async Task<RefreshRotation> RotateAsUnionAsync(string presentedRefreshToken, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
    {
        var result = await RotateWithOutcomeAsync(presentedRefreshToken, claims, cancellationToken).ConfigureAwait(false);
        return RefreshRotationMapper.ToUnion(result);
    }
}
#endif
