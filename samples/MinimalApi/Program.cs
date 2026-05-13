using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TechTeaStudio.Auth.Abstractions;
using TechTeaStudio.Auth.AspNetCore;
using TechTeaStudio.Auth.AspNetCore.Authorization;
using TechTeaStudio.Auth.EFCore;
using TechTeaStudio.Auth.Lockout;
using TechTeaStudio.Auth.RefreshTokens;
using TechTeaStudio.Auth.Swashbuckle;

var builder = WebApplication.CreateBuilder(args);

// Auth.SecretKey must come from configuration in real apps (user-secrets / env / vault).
builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
{
    ["Auth:Jwt:SecretKey"] = "dev-only-32-char-signing-key-!!!!",
    ["Auth:Jwt:Issuer"] = "tts.minimal",
    ["Auth:Jwt:Audience"] = "tts.minimal.clients",
});

builder.Services.AddTechTeaStudioAuth(builder.Configuration);
builder.Services.AddDbContext<AppDb>(o => o.UseInMemoryDatabase("tts-minimal"));
builder.Services.AddScoped<IRefreshTokenStore, EfCoreRefreshTokenStore<AppDb>>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o => o.AddTechTeaStudioBearerSwagger());

var app = builder.Build();
app.UseSecurityHeaders();
app.UseAuthentication();
app.UseAuthorization();
app.UseSwagger();
app.UseSwaggerUI();

app.MapPost("/signup", async (SignupRequest req, IPasswordHasher hasher, AppDb db) =>
{
    if (await db.Users.AnyAsync(u => u.Email == req.Email))
        return Results.Conflict(new { error = "email_taken" });
    db.Users.Add(new User { Email = req.Email, PasswordHash = hasher.Hash(req.Password) });
    await db.SaveChangesAsync();
    return Results.Created($"/me", new { req.Email });
});

app.MapPost("/login", async (LoginRequest req, IPasswordHasher hasher, RefreshTokenService refresh,
    ILoginAttemptTracker lockout, AppDb db) =>
{
    if ((await lockout.GetStatusAsync(req.Email)).IsLocked) return Results.StatusCode(429);
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == req.Email);
    if (user is null || !hasher.Verify(user.PasswordHash, req.Password))
    {
        await lockout.RecordFailureAsync(req.Email);
        return Results.Unauthorized();
    }
    await lockout.RecordSuccessAsync(req.Email);
    // Build whatever claim shape your downstream services expect.
    // Bigger apps usually implement IClaimsProfile once and reuse it.
    var claims = new[]
    {
        new Claim(AuthClaims.Username, user.Email),
        new Claim(AuthClaims.Email, user.Email),
    };
    return Results.Ok(await refresh.IssueAsync(user.Id.ToString(), claims));
});

app.MapPost("/refresh", async (RefreshRequest req, RefreshTokenService refresh) =>
{
    var pair = await refresh.RotateAsync(req.RefreshToken, Array.Empty<Claim>());
    return pair is null ? Results.Unauthorized() : Results.Ok(pair);
});

app.MapPost("/logout", async (RefreshRequest req, RefreshTokenService refresh) =>
{
    await refresh.RevokeAsync(req.RefreshToken);
    return Results.NoContent();
});

app.MapGet("/me", (ClaimsPrincipal user) => new
{
    sub = user.FindFirstValue(AuthClaims.Subject),
    email = user.FindFirstValue(AuthClaims.Email),
})
.RequireAuthorization(AuthPolicies.Authenticated);

app.Run();

public sealed class AppDb(DbContextOptions<AppDb> o) : DbContext(o)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>().HasIndex(u => u.Email).IsUnique();
        b.AddTechTeaStudioRefreshTokens();
    }
}

public sealed class User
{
    public int Id { get; set; }
    public string Email { get; set; } = "";
    public string PasswordHash { get; set; } = "";
}

public sealed record SignupRequest(string Email, string Password);
public sealed record LoginRequest(string Email, string Password);
public sealed record RefreshRequest(string RefreshToken);
