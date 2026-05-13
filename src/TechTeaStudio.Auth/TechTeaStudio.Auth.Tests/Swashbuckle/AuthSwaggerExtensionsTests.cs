using FluentAssertions;
using Swashbuckle.AspNetCore.SwaggerGen;
using TechTeaStudio.Auth.Swashbuckle;
using Xunit;

namespace TechTeaStudio.Auth.Tests.Swashbuckle;

public class AuthSwaggerExtensionsTests
{
    [Fact]
    public void AddBearerSwagger_registers_security_scheme()
    {
        var options = new SwaggerGenOptions();
        options.AddTechTeaStudioBearerSwagger();

        options.SwaggerGeneratorOptions.SecuritySchemes.Should().ContainKey(AuthSwaggerExtensions.BearerSchemeId);
        var scheme = options.SwaggerGeneratorOptions.SecuritySchemes[AuthSwaggerExtensions.BearerSchemeId];
        scheme.Scheme.Should().Be("bearer");
        scheme.BearerFormat.Should().Be("JWT");
    }

    [Fact]
    public void AutoAttach_registers_operation_filter()
    {
        var options = new SwaggerGenOptions();
        options.AddTechTeaStudioBearerSwagger(autoAttachToAuthorizedOperations: true);
        options.OperationFilterDescriptors.Should()
            .Contain(d => d.Type == typeof(AttachBearerToAuthorizedOperationsFilter));
    }

    [Fact]
    public void Auto_attach_off_skips_filter_registration()
    {
        var options = new SwaggerGenOptions();
        options.AddTechTeaStudioBearerSwagger(autoAttachToAuthorizedOperations: false);
        options.OperationFilterDescriptors.Should()
            .NotContain(d => d.Type == typeof(AttachBearerToAuthorizedOperationsFilter));
    }
}
