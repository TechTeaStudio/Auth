using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace TechTeaStudio.Auth.Swashbuckle;

/// <summary>
/// Attaches the <see cref="AuthSwaggerExtensions.BearerSchemeId"/> security
/// requirement to any operation that requires authorization. Looks at both
/// the legacy attribute surface (controller / action <see cref="AuthorizeAttribute"/>)
/// and the Minimal-API endpoint-metadata surface (<see cref="IAuthorizeData"/>),
/// so endpoints declared with <c>app.MapGet(...).RequireAuthorization()</c>
/// pick up the lock icon too.
/// </summary>
public sealed class AttachBearerToAuthorizedOperationsFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (!RequiresAuthorization(context)) return;

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

    private static bool RequiresAuthorization(OperationFilterContext context)
    {
        // Minimal API + endpoint routing — authorization lives on the endpoint metadata.
        var endpointMetadata = context.ApiDescription.ActionDescriptor.EndpointMetadata ?? Array.Empty<object>();
        var hasAuthorizeData = endpointMetadata.OfType<IAuthorizeData>().Any();
        var allowsAnonymousData = endpointMetadata.OfType<IAllowAnonymous>().Any();
        if (hasAuthorizeData && !allowsAnonymousData) return true;

        // Legacy MVC controllers — attributes on action method or declaring controller.
        var hasAuthorizeAttribute = context.MethodInfo.GetCustomAttributes(true).OfType<AuthorizeAttribute>().Any()
                                  || (context.MethodInfo.DeclaringType?.GetCustomAttributes(true).OfType<AuthorizeAttribute>().Any() ?? false);
        var allowsAnonymousAttribute = context.MethodInfo.GetCustomAttributes(true).OfType<AllowAnonymousAttribute>().Any();
        return hasAuthorizeAttribute && !allowsAnonymousAttribute;
    }
}
