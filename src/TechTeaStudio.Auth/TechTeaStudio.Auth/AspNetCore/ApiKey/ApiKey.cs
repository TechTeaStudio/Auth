using System.Security.Claims;

namespace TechTeaStudio.Auth.AspNetCore.ApiKey;

/// <summary>Outcome of <see cref="IApiKeyStore.ValidateAsync"/>.</summary>
public sealed record ApiKeyValidationResult(bool IsValid, string? SubjectId, IReadOnlyList<Claim>? Claims = null);

/// <summary>
/// Resolves a raw API key to a principal. Implementations decide where keys live
/// (config, database, secret manager). The library does not mandate a schema.
/// </summary>
public interface IApiKeyStore
{
    Task<ApiKeyValidationResult> ValidateAsync(string rawKey, CancellationToken cancellationToken = default);
}

/// <summary>Lambda-backed convenience store, useful for tests and tiny apps.</summary>
public sealed class FuncApiKeyStore : IApiKeyStore
{
    private readonly Func<string, CancellationToken, Task<ApiKeyValidationResult>> _validate;

    public FuncApiKeyStore(Func<string, CancellationToken, Task<ApiKeyValidationResult>> validate)
        => _validate = validate ?? throw new ArgumentNullException(nameof(validate));

    public Task<ApiKeyValidationResult> ValidateAsync(string rawKey, CancellationToken cancellationToken = default)
        => _validate(rawKey, cancellationToken);
}
