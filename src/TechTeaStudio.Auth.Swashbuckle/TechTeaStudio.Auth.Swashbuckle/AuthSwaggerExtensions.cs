using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace TechTeaStudio.Auth.Swashbuckle;

/// <summary>
/// Adds the JWT-Bearer security scheme to Swashbuckle so the Swagger UI's
/// "Authorize" button works end-to-end against a TechTeaStudio.Auth-protected API.
/// </summary>
public static class AuthSwaggerExtensions
{
    /// <summary>Stable scheme id used in the OpenAPI <c>securitySchemes</c> dictionary.</summary>
    public const string BearerSchemeId = "Bearer";

    /// <summary>
    /// Registers <see cref="BearerSchemeId"/> as a Bearer / JWT security scheme.
    /// When <paramref name="autoAttachToAuthorizedOperations"/> is <c>true</c> (default),
    /// every operation marked <c>[Authorize]</c> gets the scheme attached automatically —
    /// the consumer does not have to add a <c>SecurityRequirement</c> per endpoint.
    /// </summary>
    public static SwaggerGenOptions AddTechTeaStudioBearerSwagger(
        this SwaggerGenOptions options,
        bool autoAttachToAuthorizedOperations = true)
    {
        if (options is null) throw new ArgumentNullException(nameof(options));

        options.SwaggerGeneratorOptions.SecuritySchemes[BearerSchemeId] = new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Paste the JWT access token (without the \"Bearer \" prefix). "
                        + "The Swagger UI sends it as `Authorization: Bearer <token>`. "
                        + "Issued by TechTeaStudio.Auth — see /docs/RECIPES.md for how to obtain one.",
        };

        if (autoAttachToAuthorizedOperations)
            options.OperationFilterDescriptors.Add(new FilterDescriptor
            {
                Type = typeof(AttachBearerToAuthorizedOperationsFilter),
                Arguments = Array.Empty<object>(),
            });

        return options;
    }
}
