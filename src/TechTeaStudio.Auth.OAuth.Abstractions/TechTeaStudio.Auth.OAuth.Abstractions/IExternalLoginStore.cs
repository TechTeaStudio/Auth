namespace TechTeaStudio.Auth.OAuth;

/// <summary>
/// Storage contract for <see cref="ExternalLogin"/> rows. Implementations live in
/// <c>TechTeaStudio.Auth.OAuth.EFCore</c>, future <c>.Redis</c>, or consumer-side.
/// Default registration is <see cref="InMemoryExternalLoginStore"/> — single-instance only.
/// </summary>
public interface IExternalLoginStore
{
    /// <summary>Returns the link for <c>(provider, providerUserId)</c> if any.</summary>
    Task<ExternalLogin?> FindAsync(string provider, string providerUserId, CancellationToken cancellationToken = default);

    /// <summary>Returns every link owned by <paramref name="userId"/>.</summary>
    Task<IReadOnlyList<ExternalLogin>> GetForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>Persists a new link. Throws <see cref="InvalidOperationException"/> on duplicate.</summary>
    Task CreateAsync(ExternalLogin login, CancellationToken cancellationToken = default);

    /// <summary>Removes the link with the given id. No-op when unknown.</summary>
    Task DeleteAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>Removes every link owned by <paramref name="userId"/> (account deletion).</summary>
    Task DeleteAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}
