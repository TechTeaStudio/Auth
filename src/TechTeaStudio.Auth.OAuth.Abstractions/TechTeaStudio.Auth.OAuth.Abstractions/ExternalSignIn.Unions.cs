#if NET11_0_OR_GREATER
using TechTeaStudio.Auth.RefreshTokens;

namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// The user is signed in: the external identity is linked to <paramref name="UserId"/> and
/// <paramref name="Tokens"/> is the issued access + refresh pair. Maps
/// <see cref="ExternalSignInStatus.Authenticated"/>.
/// </summary>
/// <param name="Tokens">The issued pair. Never <c>null</c>.</param>
/// <param name="UserId">
/// Id of the user the tokens were issued for, as the host's <see cref="IExternalUserBridge"/>
/// reported it. It equals the <c>sub</c> claim of the access token.
/// </param>
public sealed record ExternalSignedIn(TokenPair Tokens, string UserId);

/// <summary>
/// The provider's e-mail matches an existing password account. Ask the user for that account's
/// password and pass it with <paramref name="ContinuationToken"/> to
/// <see cref="ExternalLoginService.LinkExistingAccountAsUnionAsync"/>. Maps
/// <see cref="ExternalSignInStatus.RequiresPassword"/>.
/// </summary>
/// <param name="ContinuationToken">Signed, single-use, valid for 10 minutes.</param>
/// <param name="Email">The e-mail returned by the provider, for prefilling the prompt.</param>
public sealed record ExternalPasswordRequired(string ContinuationToken, string Email);

/// <summary>
/// No matching user. Ask the user to pick a username and pass it with
/// <paramref name="ContinuationToken"/> to
/// <see cref="ExternalLoginService.CompleteRegistrationAsUnionAsync"/>. Maps
/// <see cref="ExternalSignInStatus.RequiresRegistration"/>.
/// </summary>
/// <param name="ContinuationToken">Signed, single-use, valid for 10 minutes.</param>
/// <param name="Profile">The profile fetched from the provider, for suggesting a username and showing the avatar.</param>
public sealed record ExternalRegistrationRequired(string ContinuationToken, ExternalLoginInfo Profile);

/// <summary>
/// The provider rejected the credential or the orchestrator could not finish. Maps
/// <see cref="ExternalSignInStatus.Failed"/>.
/// </summary>
/// <param name="Error">
/// Short stable string suitable for switching client-side (<c>invalid_credential</c>,
/// <c>unknown_provider</c>, <c>invalid_password</c>, ...): the same strings
/// <see cref="ExternalSignInOutcome.Error"/> carries.
/// </param>
public sealed record ExternalSignInFailed(string Error);

/// <summary>
/// Result of <see cref="ExternalLoginService.SignInAsUnionAsync"/> as a C# 15 union: exactly
/// one of <see cref="ExternalSignedIn"/>, <see cref="ExternalPasswordRequired"/>,
/// <see cref="ExternalRegistrationRequired"/> or <see cref="ExternalSignInFailed"/>. A
/// <c>switch</c> over the four case types is exhaustive, and each case carries only the data
/// that exists for it, all of it non-null.
/// </summary>
/// <remarks>
/// <para>
/// <c>net11.0</c> only. It carries the same information as <see cref="ExternalSignInOutcome"/>
/// (plus the user id) and is produced from it; the older targets keep using
/// <see cref="ExternalSignInOutcome"/>.
/// </para>
/// <para>
/// A <c>switch</c> expression with the four case arms and no <c>null</c> arm compiles without
/// a warning (checked on SDK 11.0.100), and leaving a case out is warning CS8509, which names
/// the missing case. A value returned by the library always holds a case, so no <c>null</c> arm
/// is needed. <c>default(ExternalSignIn)</c> holds nothing (its <c>Value</c> is <c>null</c>)
/// and makes such a switch throw <c>SwitchExpressionException</c> at run time, so do not use
/// <c>default</c> as a placeholder.
/// </para>
/// <para>
/// Do not return this type from an HTTP endpoint. A union has no discriminator on the wire, so
/// token pairs and continuation tokens would be serialized as an undiscriminated <c>anyOf</c>.
/// Switch on it and map each case to your own DTO.
/// </para>
/// <para>
/// Adding a case is a breaking change for every exhaustive <c>switch</c> and is released as one.
/// </para>
/// </remarks>
public union ExternalSignIn(ExternalSignedIn, ExternalPasswordRequired, ExternalRegistrationRequired, ExternalSignInFailed);

/// <summary>
/// Result of the steps that finish a sign-in
/// (<see cref="ExternalLoginService.LinkExistingAccountAsUnionAsync"/>,
/// <see cref="ExternalLoginService.CompleteRegistrationAsUnionAsync"/>,
/// <see cref="ExternalLoginService.LinkToUserAsUnionAsync"/>) as a C# 15 union: either
/// <see cref="ExternalSignedIn"/> or <see cref="ExternalSignInFailed"/>. Those steps never ask
/// for another step, and this type says so: there is no "requires password" or "requires
/// registration" case to handle.
/// </summary>
/// <remarks>
/// <c>net11.0</c> only. The notes on <see cref="ExternalSignIn"/> apply: a library-returned
/// value always holds a case, do not return it from an HTTP endpoint (map it to your own DTO),
/// and adding a case is a breaking change.
/// </remarks>
public union ExternalSignInCompletion(ExternalSignedIn, ExternalSignInFailed);
#endif
