using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TechTeaStudio.Auth.OAuth.Microsoft;
using Xunit;

namespace TechTeaStudio.Auth.Tests.OAuth;

/// <summary>
/// Covers the part of the Microsoft provider that is actually security-critical: what it accepts
/// as a valid id_token. Entra is replaced by a stub handler serving its two endpoints (token and
/// JWKS) from a throwaway RSA key, so the tests exercise the real
/// <see cref="JwtSecurityTokenHandler"/> validation path without touching the network.
/// </summary>
public class MicrosoftAuthProviderTests : IDisposable
{
    private const string ClientId = "11111111-2222-3333-4444-555555555555";
    private const string HomeTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string OtherTenant = "ffffffff-9999-8888-7777-666666666666";
    private const string ObjectId = "0dc0ffee-cafe-4bad-9999-000000000001";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _instance = $"https://login.{Guid.NewGuid():N}.invalid";

    public void Dispose() => _rsa.Dispose();

    private sealed class Monitor : IOptionsMonitor<MicrosoftAuthProviderOptions>
    {
        public MicrosoftAuthProviderOptions Current { get; set; } = new();
        public MicrosoftAuthProviderOptions CurrentValue => Current;
        public MicrosoftAuthProviderOptions Get(string? _) => Current;
        public IDisposable? OnChange(Action<MicrosoftAuthProviderOptions, string?> _) => null;
    }

    /// <summary>Stands in for Entra: /token hands back whatever id_token the test built, and
    /// /discovery/v2.0/keys publishes the matching public key.</summary>
    private sealed class EntraStub : HttpMessageHandler
    {
        private readonly string _jwks;
        private readonly string? _idToken;
        private readonly HttpStatusCode _tokenStatus;

        public EntraStub(string jwks, string? idToken, HttpStatusCode tokenStatus = HttpStatusCode.OK)
        {
            _jwks = jwks;
            _idToken = idToken;
            _tokenStatus = tokenStatus;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path.EndsWith("/discovery/v2.0/keys", StringComparison.Ordinal))
                return Task.FromResult(Json(HttpStatusCode.OK, _jwks));

            if (path.EndsWith("/oauth2/v2.0/token", StringComparison.Ordinal))
                return Task.FromResult(_tokenStatus == HttpStatusCode.OK
                    ? Json(HttpStatusCode.OK, $"{{\"token_type\":\"Bearer\",\"id_token\":\"{_idToken}\"}}")
                    : Json(_tokenStatus, "{\"error\":\"invalid_grant\"}"));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }

    private string Jwks()
    {
        var parameters = _rsa.ExportParameters(includePrivateParameters: false);
        var n = Base64UrlEncoder.Encode(parameters.Modulus);
        var e = Base64UrlEncoder.Encode(parameters.Exponent);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"test-key\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    private string IdToken(
        string? audience = ClientId,
        string tenantForIssuer = HomeTenant,
        string tenantClaim = HomeTenant,
        string? email = "founder@techteastudio.cc",
        DateTime? expires = null)
    {
        var key = new RsaSecurityKey(_rsa) { KeyId = "test-key" };
        var claims = new List<Claim>
        {
            new("tid", tenantClaim),
            new("oid", ObjectId),
            new("name", "Iaroslav Ulantikov"),
            new("preferred_username", "founder@techteastudio.cc"),
        };
        if (email is not null) claims.Add(new Claim("email", email));

        // nbf/iat are anchored to exp rather than to now, so an expired token stays internally
        // consistent - JwtSecurityTokenHandler refuses to even build one whose exp precedes nbf.
        var exp = expires ?? DateTime.UtcNow.AddMinutes(10);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = $"{_instance}/{tenantForIssuer}/v2.0",
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = exp.AddMinutes(-12),
            IssuedAt = exp.AddMinutes(-11),
            Expires = exp,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        };

        var handler = new JwtSecurityTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateEncodedJwt(descriptor);
    }

    private MicrosoftAuthProvider Sut(string? idToken, MicrosoftAuthProviderOptions? options = null, HttpStatusCode tokenStatus = HttpStatusCode.OK)
    {
        var http = new HttpClient(new EntraStub(Jwks(), idToken, tokenStatus));
        var opts = options ?? new MicrosoftAuthProviderOptions
        {
            ClientId = ClientId,
            ClientSecret = "secret",
            RedirectUri = "https://chronos.example/auth/microsoft/callback",
            TenantId = "common",
            Instance = _instance,
        };
        return new MicrosoftAuthProvider(http, new Monitor { Current = opts });
    }

    [Fact]
    public void Name_is_Microsoft() => Sut(idToken: null).Name.Should().Be("Microsoft");

    [Fact]
    public async Task Valid_token_maps_onto_ExternalLoginInfo()
    {
        var info = await Sut(IdToken()).ValidateAsync("auth-code");

        info.Should().NotBeNull();
        info!.Provider.Should().Be("Microsoft");
        // oid alone repeats across tenants, so the stored key is tenant-scoped.
        info.ProviderUserId.Should().Be($"{HomeTenant}.{ObjectId}");
        info.Email.Should().Be("founder@techteastudio.cc");
        info.DisplayName.Should().Be("Iaroslav Ulantikov");
        info.AvatarUrl.Should().BeNull();
    }

    [Fact]
    public async Task Token_minted_for_another_application_is_refused()
    {
        var info = await Sut(IdToken(audience: "some-other-app")).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Issuer_that_disagrees_with_the_tid_claim_is_refused()
    {
        // The exact forgery the manual issuer check exists for: a token whose tid says one tenant
        // while the issuer URL says another.
        var info = await Sut(IdToken(tenantForIssuer: OtherTenant, tenantClaim: HomeTenant)).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Single_tenant_configuration_refuses_a_foreign_tenant()
    {
        var options = new MicrosoftAuthProviderOptions
        {
            ClientId = ClientId,
            ClientSecret = "secret",
            RedirectUri = "https://chronos.example/auth/microsoft/callback",
            TenantId = HomeTenant,
            Instance = _instance,
        };
        var foreign = IdToken(tenantForIssuer: OtherTenant, tenantClaim: OtherTenant);

        var info = await Sut(foreign, options).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Expired_token_is_refused()
    {
        var info = await Sut(IdToken(expires: DateTime.UtcNow.AddMinutes(-30))).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Token_endpoint_failure_returns_null()
    {
        var info = await Sut(IdToken(), tokenStatus: HttpStatusCode.BadRequest).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Missing_redirect_uri_short_circuits_before_any_http_call()
    {
        var options = new MicrosoftAuthProviderOptions
        {
            ClientId = ClientId,
            ClientSecret = "secret",
            RedirectUri = null,
            Instance = _instance,
        };
        var info = await Sut(IdToken(), options).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Missing_client_credentials_returns_null()
    {
        var options = new MicrosoftAuthProviderOptions
        {
            ClientId = null,
            ClientSecret = null,
            RedirectUri = "https://chronos.example/auth/microsoft/callback",
            Instance = _instance,
        };
        var info = await Sut(IdToken(), options).ValidateAsync("auth-code");
        info.Should().BeNull();
    }

    [Fact]
    public async Task Work_account_without_an_email_claim_falls_back_to_the_upn()
    {
        var info = await Sut(IdToken(email: null)).ValidateAsync("auth-code");

        info.Should().NotBeNull();
        info!.Email.Should().Be("founder@techteastudio.cc");
    }

    [Fact]
    public async Task Empty_credential_returns_null()
    {
        var info = await Sut(IdToken()).ValidateAsync("");
        info.Should().BeNull();
    }
}
