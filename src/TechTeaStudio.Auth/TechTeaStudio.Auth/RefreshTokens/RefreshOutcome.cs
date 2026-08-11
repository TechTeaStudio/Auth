namespace TechTeaStudio.Auth.RefreshTokens;

/// <summary>
/// Discriminates why <see cref="RefreshTokenService.RotateWithOutcomeAsync(string, System.Threading.CancellationToken)"/>
/// did or did not mint a new token pair. The plain <c>TokenPair?</c>-returning
/// <c>RotateAsync</c> overloads collapse every non-success case to <c>null</c> — use this
/// API when the caller needs to react differently to a stolen-token signal (force logout
/// everywhere, alert the user) than to an ordinary expired or unknown token (just prompt
/// re-login).
/// </summary>
public enum RefreshOutcome
{
    /// <summary>Rotation succeeded — a new token pair was issued.</summary>
    Success,

    /// <summary>
    /// The presented token could not be redeemed: it is unknown (never issued, or already
    /// hard-deleted), or it lost a same-instant compare-and-swap race against a concurrent
    /// rotation of the SAME still-valid token. The latter is a deliberate safe-reject choice —
    /// see the remarks on <see cref="RefreshTokenService.RotateWithOutcomeAsync(string, System.Collections.Generic.IEnumerable{System.Security.Claims.Claim}, System.Threading.CancellationToken)"/>
    /// for why a lost race does not burn the family.
    /// </summary>
    Invalid,

    /// <summary>
    /// The presented token was found but its lifetime has passed and it was never revoked —
    /// an ordinary stale token, not a reuse signal. The family is left intact.
    /// </summary>
    Expired,

    /// <summary>
    /// The presented token was already used (rotated away) or explicitly revoked by a
    /// distinct, completed prior operation — a second presentation of a spent token is the
    /// stolen-token signal. The entire rotation family, including whatever token it was
    /// rotated into, has been revoked; every device sharing this family must re-login.
    /// </summary>
    ReusedFamilyRevoked,
}

/// <summary>
/// Result of an outcome-aware rotation. <see cref="Tokens"/> is non-null if and only if
/// <see cref="Outcome"/> is <see cref="RefreshOutcome.Success"/>.
/// </summary>
public sealed record RefreshRotationResult(RefreshOutcome Outcome, TokenPair? Tokens)
{
    internal static readonly RefreshRotationResult Invalid = new(RefreshOutcome.Invalid, null);
    internal static readonly RefreshRotationResult Expired = new(RefreshOutcome.Expired, null);
    internal static readonly RefreshRotationResult ReusedFamilyRevoked = new(RefreshOutcome.ReusedFamilyRevoked, null);
    internal static RefreshRotationResult Success(TokenPair tokens) => new(RefreshOutcome.Success, tokens);
}
