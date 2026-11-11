#if NET11_0_OR_GREATER
using System.Diagnostics;

namespace TechTeaStudio.Auth.OAuth;

public sealed partial class ExternalLoginService
{
    /// <summary>
    /// Union-returning form of <see cref="SignInAsync"/>: validates the provider's credential and
    /// reports the result as an <see cref="ExternalSignIn"/>, so a <c>switch</c> over it is
    /// checked for exhaustiveness and each case carries only its own, non-null data.
    /// <c>net11.0</c> only.
    /// </summary>
    /// <remarks>Calls <see cref="SignInAsync"/> and converts its outcome; the flow is exactly that method's.</remarks>
    public async Task<ExternalSignIn> SignInAsUnionAsync(string provider, string rawCredential, CancellationToken cancellationToken = default)
    {
        var outcome = await SignInAsync(provider, rawCredential, cancellationToken).ConfigureAwait(false);
        return ToUnion(outcome, nameof(SignInAsync));
    }

    /// <summary>
    /// Union-returning form of <see cref="LinkExistingAccountAsync"/>: completes the
    /// <see cref="ExternalPasswordRequired"/> branch. The user proves ownership of the existing
    /// account by typing its password, and the OAuth identity is linked to that account.
    /// <c>net11.0</c> only.
    /// </summary>
    /// <remarks>
    /// Calls <see cref="LinkExistingAccountAsync"/> and converts its outcome. As there, the
    /// continuation token is spent by the attempt, wrong password included.
    /// </remarks>
    public async Task<ExternalSignInCompletion> LinkExistingAccountAsUnionAsync(string continuationToken, string password, CancellationToken cancellationToken = default)
    {
        var outcome = await LinkExistingAccountAsync(continuationToken, password, cancellationToken).ConfigureAwait(false);
        return ToCompletion(outcome, nameof(LinkExistingAccountAsync));
    }

    /// <summary>
    /// Union-returning form of <see cref="CompleteRegistrationAsync"/>: completes the
    /// <see cref="ExternalRegistrationRequired"/> branch. Creates a new password-less account in
    /// the consumer's user store and links the OAuth identity. <c>net11.0</c> only.
    /// </summary>
    /// <remarks>Calls <see cref="CompleteRegistrationAsync"/> and converts its outcome.</remarks>
    public async Task<ExternalSignInCompletion> CompleteRegistrationAsUnionAsync(string continuationToken, string username, CancellationToken cancellationToken = default)
    {
        var outcome = await CompleteRegistrationAsync(continuationToken, username, cancellationToken).ConfigureAwait(false);
        return ToCompletion(outcome, nameof(CompleteRegistrationAsync));
    }

    /// <summary>
    /// Union-returning form of <see cref="LinkToUserAsync"/>: links a provider identity to an
    /// **already-authenticated** user. Caller is responsible for verifying that
    /// <paramref name="userId"/> matches the current <c>HttpContext.User</c>. <c>net11.0</c> only.
    /// </summary>
    /// <remarks>Calls <see cref="LinkToUserAsync"/> and converts its outcome.</remarks>
    public async Task<ExternalSignInCompletion> LinkToUserAsUnionAsync(string provider, string rawCredential, string userId, CancellationToken cancellationToken = default)
    {
        var outcome = await LinkToUserAsync(provider, rawCredential, userId, cancellationToken).ConfigureAwait(false);
        return ToCompletion(outcome, nameof(LinkToUserAsync));
    }

    /// <summary>
    /// The single place an <see cref="ExternalSignInOutcome"/> becomes a union case. It enforces
    /// what the outcome record cannot express: the fields a status promises are really there.
    /// </summary>
    /// <param name="outcome">The outcome of one of the classic methods.</param>
    /// <param name="source">Name of the method that produced it, for the exception message.</param>
    /// <exception cref="InvalidOperationException">A field the status requires is missing.</exception>
    /// <exception cref="UnreachableException">The status is a value this mapper does not know.</exception>
    private static ExternalSignIn ToUnion(ExternalSignInOutcome outcome, string source)
    {
        switch (outcome.Status)
        {
            case ExternalSignInStatus.Authenticated:
                return new ExternalSignedIn(
                    outcome.Tokens ?? throw Missing(source, outcome.Status, "token pair"),
                    Required(outcome.UserId, source, outcome.Status, "user id"));

            case ExternalSignInStatus.RequiresPassword:
                return new ExternalPasswordRequired(
                    Required(outcome.ContinuationToken, source, outcome.Status, "continuation token"),
                    Required(outcome.Email, source, outcome.Status, "e-mail"));

            case ExternalSignInStatus.RequiresRegistration:
                return new ExternalRegistrationRequired(
                    Required(outcome.ContinuationToken, source, outcome.Status, "continuation token"),
                    outcome.Profile ?? throw Missing(source, outcome.Status, "provider profile"));

            case ExternalSignInStatus.Failed:
                return new ExternalSignInFailed(Required(outcome.Error, source, outcome.Status, "error"));

            default:
                throw new UnreachableException($"Unmapped {nameof(ExternalSignInStatus)} value '{outcome.Status}' from {source}.");
        }
    }

    /// <summary>
    /// Narrows the mapped outcome of a completion method to the two cases such a method can end
    /// in. A <c>Requires*</c> status there would mean the orchestrator asked for a further step
    /// from a step that has none, so it throws instead of inventing a case.
    /// </summary>
    /// <exception cref="InvalidOperationException">The outcome is a <c>Requires*</c> status.</exception>
    private static ExternalSignInCompletion ToCompletion(ExternalSignInOutcome outcome, string source) =>
        ToUnion(outcome, source).Value switch
        {
            ExternalSignedIn signedIn => signedIn,
            ExternalSignInFailed failed => failed,
            _ => throw new InvalidOperationException(
                $"{source} returned {outcome.Status}, but a completion step can only end in " +
                $"{nameof(ExternalSignInStatus.Authenticated)} or {nameof(ExternalSignInStatus.Failed)}."),
        };

    private static string Required(string? value, string source, ExternalSignInStatus status, string what) =>
        string.IsNullOrEmpty(value) ? throw Missing(source, status, what) : value;

    private static InvalidOperationException Missing(string source, ExternalSignInStatus status, string what) =>
        new($"{source} returned {status} without a {what}.");
}
#endif
