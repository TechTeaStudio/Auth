namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Adapter between the OAuth library and the consumer's user table. The library
/// knows nothing about the consumer's user schema; the consumer implements this
/// interface against their own repository / DbContext / external user service.
/// </summary>
public interface IExternalUserBridge
{
    /// <summary>Look up a user by email. Returns <c>null</c> when no such user exists.</summary>
    Task<ExternalUserSnapshot?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>Look up a user by id (string form, as written into <c>sub</c>).</summary>
    Task<ExternalUserSnapshot?> GetByIdAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new user from <paramref name="info"/> plus the username chosen
    /// during the registration flow. New users are password-less by default —
    /// implementations should leave <see cref="ExternalUserSnapshot.PasswordHash"/>
    /// null and may mark the email as verified when
    /// <see cref="ExternalLoginInfo.EmailVerified"/> is true.
    /// </summary>
    Task<ExternalUserSnapshot> CreateFromExternalAsync(ExternalLoginInfo info, string username, CancellationToken cancellationToken = default);
}
