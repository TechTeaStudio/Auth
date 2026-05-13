using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.Extensions.Options;
using TechTeaStudio.Auth.Signing;

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

        // Signing key check — either Signing.Keys is populated, or SecretKey is.
        if (options.Signing.Keys.Count == 0)
        {
            if (string.IsNullOrEmpty(options.SecretKey))
                failures.Add("AuthOptions.SecretKey is required when AuthOptions.Signing.Keys is empty.");
            else if (Encoding.UTF8.GetByteCount(options.SecretKey) < 32)
                failures.Add("AuthOptions.SecretKey must be at least 32 bytes (256 bits) when UTF-8-encoded.");
        }
        else
        {
            // Validate each descriptor by asking the resolver to build a security key.
            foreach (var k in options.Signing.Keys)
            {
                if (string.IsNullOrEmpty(k.Kid))
                {
                    failures.Add("AuthOptions.Signing.Keys[*].Kid is required.");
                    continue;
                }
                try { _ = SigningKeyResolver.BuildValidationKey(k); }
                catch (Exception ex) { failures.Add($"Signing.Keys['{k.Kid}']: {ex.Message}"); }
            }

            if (!string.IsNullOrEmpty(options.Signing.ActiveKid)
                && !options.Signing.Keys.Any(k => k.Kid == options.Signing.ActiveKid))
            {
                failures.Add($"Signing.ActiveKid '{options.Signing.ActiveKid}' is not present in Signing.Keys.");
            }
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
