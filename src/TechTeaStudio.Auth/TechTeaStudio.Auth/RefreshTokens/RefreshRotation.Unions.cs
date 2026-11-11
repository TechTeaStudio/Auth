#if NET11_0_OR_GREATER
using System.Diagnostics;

namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Rotation succeeded: the presented refresh token is spent and <paramref name="Tokens"/> is the
/// new access + refresh pair. Maps <see cref="RefreshOutcome.Success"/>.
/// </summary>
/// <param name="Tokens">The freshly issued pair. Never <c>null</c>.</param>
public sealed record RefreshRotated(TokenPair Tokens);

/// <summary>
/// The presented token could not be redeemed: it is unknown (never issued, or already
/// hard-deleted), empty, or it lost a same-instant compare-and-swap race against a concurrent
/// rotation of the same still-valid token. The family is left intact. Maps
/// <see cref="RefreshOutcome.Invalid"/>.
/// </summary>
public sealed record RefreshTokenInvalid;

/// <summary>
/// The presented token was found but its lifetime has passed and it was never revoked: an
/// ordinary stale token, not a reuse signal. The family is left intact. Maps
/// <see cref="RefreshOutcome.Expired"/>.
/// </summary>
public sealed record RefreshTokenExpired;

/// <summary>
/// The presented token was already used or revoked by a distinct, completed prior operation:
/// the stolen-token signal. The whole rotation family has been revoked when
/// <see cref="RefreshTokenOptions.RevokeChainOnReuse"/> is on, so every device sharing it must
/// log in again. Maps <see cref="RefreshOutcome.ReusedFamilyRevoked"/>.
/// </summary>
public sealed record RefreshTokenReused;

/// <summary>
/// Result of <see cref="RefreshTokenService.RotateAsUnionAsync(string, System.Threading.CancellationToken)"/>
/// as a C# 15 union: exactly one of <see cref="RefreshRotated"/>, <see cref="RefreshTokenInvalid"/>,
/// <see cref="RefreshTokenExpired"/> or <see cref="RefreshTokenReused"/>. A <c>switch</c> over
/// the four case types is exhaustive, so the compiler checks that every outcome is handled, and
/// the token pair exists only on the case that has one.
/// </summary>
/// <remarks>
/// <para>
/// <c>net11.0</c> only. It carries the same information as <see cref="RefreshRotationResult"/>
/// and is produced from it; the older targets keep using <see cref="RefreshRotationResult"/>.
/// </para>
/// <para>
/// A <c>switch</c> expression with the four case arms and no <c>null</c> arm compiles without
/// a warning (checked on SDK 11.0.100), and leaving a case out is warning CS8509, which names
/// the missing case. A value returned by the library always holds a case, so no <c>null</c> arm
/// is needed. <c>default(RefreshRotation)</c> holds nothing (its <c>Value</c> is <c>null</c>)
/// and makes such a switch throw <c>SwitchExpressionException</c> at run time, so do not use
/// <c>default</c> as a placeholder.
/// </para>
/// <para>
/// Do not return this type from an HTTP endpoint. A union has no discriminator on the wire, so
/// the token pair would be serialized as an undiscriminated <c>anyOf</c>. Switch on it and map
/// each case to your own response.
/// </para>
/// <para>
/// Adding a case is a breaking change for every exhaustive <c>switch</c> and is released as one.
/// </para>
/// </remarks>
public union RefreshRotation(RefreshRotated, RefreshTokenInvalid, RefreshTokenExpired, RefreshTokenReused);

/// <summary>
/// The single place a <see cref="RefreshRotationResult"/> becomes a <see cref="RefreshRotation"/>.
/// </summary>
internal static class RefreshRotationMapper
{
    /// <summary>Maps an outcome-aware rotation result onto its union case.</summary>
    /// <exception cref="InvalidOperationException">
    /// The result says <see cref="RefreshOutcome.Success"/> but carries no token pair.
    /// </exception>
    /// <exception cref="UnreachableException">
    /// The result carries a <see cref="RefreshOutcome"/> value this mapper does not know. A new
    /// enum member must get a case here (and, if it is a new outcome, in the union).
    /// </exception>
    internal static RefreshRotation ToUnion(RefreshRotationResult result)
    {
        if (result is null) throw new ArgumentNullException(nameof(result));

        return result.Outcome switch
        {
            RefreshOutcome.Success => new RefreshRotated(result.Tokens
                ?? throw new InvalidOperationException("A successful refresh rotation carries no token pair.")),
            RefreshOutcome.Invalid => new RefreshTokenInvalid(),
            RefreshOutcome.Expired => new RefreshTokenExpired(),
            RefreshOutcome.ReusedFamilyRevoked => new RefreshTokenReused(),
            _ => throw new UnreachableException($"Unmapped {nameof(RefreshOutcome)} value '{result.Outcome}'."),
        };
    }
}
#endif
