using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore.Cookies;
using TechTeaStudio.Auth.Samples.BlazorServer.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();

builder.Services.AddAuthentication(TechTeaStudioCookieDefaults.SchemeName)
    .AddTechTeaStudioCookieAuth();
builder.Services.AddAuthorization(o => o.DefaultPolicy = new AuthorizationPolicyBuilder()
    .AddAuthenticationSchemes(TechTeaStudioCookieDefaults.SchemeName)
    .RequireAuthenticatedUser()
    .Build());
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAntiforgery();

var app = builder.Build();

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

// Sign-in endpoint — a real app authenticates with IPasswordHasher first.
app.MapPost("/sign-in", async (HttpContext ctx, string email) =>
{
    var identity = new ClaimsIdentity(new[]
    {
        new Claim(AuthClaims.Subject, email),
        new Claim(AuthClaims.Username, email),
        new Claim(AuthClaims.Email, email),
    }, TechTeaStudioCookieDefaults.SchemeName);
    await ctx.SignInAsync(TechTeaStudioCookieDefaults.SchemeName, new ClaimsPrincipal(identity));
    return Results.Redirect("/");
});

app.MapPost("/sign-out", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(TechTeaStudioCookieDefaults.SchemeName);
    return Results.Redirect("/");
});

app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
