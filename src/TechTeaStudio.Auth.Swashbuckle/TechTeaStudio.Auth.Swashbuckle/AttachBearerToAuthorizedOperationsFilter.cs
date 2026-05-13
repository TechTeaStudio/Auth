using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace TechTeaStudio.Auth.Swashbuckle;

/// <summary>
/// Attaches the <see cref="AuthSwaggerExtensions.BearerSchemeId"/> security requirement
/// to any operation whose action method or controller is decorated with
/// <see cref="AuthorizeAttribute"/> (and is not overridden by <see cref="AllowAnonymousAttribute"/>).
/// </summary>
public sealed class AttachBearerToAuthorizedOperationsFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var hasAuthorize = context.MethodInfo.GetCustomAttributes(true).OfType<AuthorizeAttribute>().Any()
                        || (context.MethodInfo.DeclaringType?.GetCustomAttributes(true).OfType<AuthorizeAttribute>().Any() ?? false);

        var allowsAnonymous = context.MethodInfo.GetCustomAttributes(true).OfType<AllowAnonymousAttribute>().Any();

        if (!hasAuthorize || allowsAnonymous) return;

        operation.Security ??= new List<OpenApiSecurityRequirement>();
        operation.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = AuthSwaggerExtensions.BearerSchemeId,
                },
            }] = Array.Empty<string>(),
        });
    }
}
