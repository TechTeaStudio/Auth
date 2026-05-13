using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.Extensions.Options;

namespace TechTeaStudio.Auth.AspNetCore;

/// <summary>
/// Validates <see cref="AuthOptions"/> beyond the per-property DataAnnotations:
/// enforces a 256-bit signing key in bytes (not characters) and a sane relationship
/// between the access-token lifetime and the refresh-token lifetime.
/// </summary>
public sealed class AuthOptionsValidator : IValidateOptions<AuthOptions>
{
    public ValidateOptionsResult Validate(string? name, AuthOptions options)
    {
        if (options is null) return ValidateOptionsResult.Fail("AuthOptions is null.");

        var failures = new List<string>();

        // DataAnnotations: per-property rules.
        var ctx = new ValidationContext(options);
        var results = new List<ValidationResult>();
        if (!Validator.TryValidateObject(options, ctx, results, validateAllProperties: true))
            failures.AddRange(results.Select(r => r.ErrorMessage ?? "validation error"));

        // Cross-property + byte-length checks.
        if (!string.IsNullOrEmpty(options.SecretKey)
            && Encoding.UTF8.GetByteCount(options.SecretKey) < 32)
        {
            failures.Add("AuthOptions.SecretKey must be at least 32 bytes (256 bits) when UTF-8-encoded.");
        }

        if (options.TokenLifetime <= TimeSpan.Zero)
            failures.Add("AuthOptions.TokenLifetime must be positive.");

        if (options.RefreshTokenLifetime <= options.TokenLifetime)
            failures.Add("AuthOptions.RefreshTokenLifetime must be greater than TokenLifetime.");

        if (options.ClockSkew < TimeSpan.Zero)
            failures.Add("AuthOptions.ClockSkew must not be negative.");

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }
}
