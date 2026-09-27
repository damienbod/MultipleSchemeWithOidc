using BffOpenId.Server;
using BffOpenId.Server.Services;
using Duende.IdentityModel;
using Idp.Swiyu.Passkeys.ServiceDefaults;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.AddServerHeader = false;
});

var services = builder.Services;
var configuration = builder.Configuration;

var stsServer = configuration["WebOidcAuthority"];

services.AddSecurityHeaderPolicies()
    .SetPolicySelector(ctx =>
    {
        if (ctx.HttpContext.Request.Path.StartsWithSegments("/api"))
        {
            return ApiSecurityHeadersDefinitions.GetHeaderPolicyCollection(builder.Environment.IsDevelopment());
        }

        return SecurityHeadersDefinitions.GetHeaderPolicyCollection(
            builder.Environment.IsDevelopment(), stsServer);
    });

services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "__Host-Http-X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

services.AddHttpClient();
services.AddOptions();

var webDpopClientPrivatePem = ConfigConverter.GetPemFromBase64Config("WebDpopClientPrivatePemBase64", builder.Configuration);
var webDpopClientPublicPem = ConfigConverter.GetPemFromBase64Config("WebDpopClientPublicPemBase64", builder.Configuration);

var ecdsaCertificate = X509Certificate2.CreateFromPem(webDpopClientPublicPem, webDpopClientPrivatePem);
var ecdsaCertificateKey = new ECDsaSecurityKey(ecdsaCertificate.GetECDsaPrivateKey());

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Unknown";
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie("SchemeOne", options =>
{
    options.Cookie.Name = "__Host-Http-one";
    options.Cookie.SameSite = SameSiteMode.Lax;
})
.AddCookie("SchemeTwo", options =>
{
    options.Cookie.Name = "__Host-Http-two";
    options.Cookie.SameSite = SameSiteMode.Lax;
})
.AddCookie("SchemeOidcAuth", options =>
{
})
.AddOpenIdConnect(options =>
{
    options.SignInScheme = "SchemeOidcAuth";

    options.Events = OidcEventHandlers.OidcEvents(builder.Configuration);

    options.ClientId = builder.Configuration["WebOidcClientId"];
    options.Authority = builder.Configuration["WebOidcAuthority"];
    options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.ResponseType = OpenIdConnectResponseType.Code;

    // client_assertion used, set in oidc events
    //options.ClientSecret = "test";

    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.MapInboundClaims = false;

    options.ClaimActions.MapUniqueJsonKey("loa", "loa");
    options.ClaimActions.MapUniqueJsonKey("loi", "loi");
    options.ClaimActions.MapUniqueJsonKey(JwtClaimTypes.Email, JwtClaimTypes.Email);

    options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Require;

    options.Scope.Add("scope2");
    options.TokenValidationParameters = new TokenValidationParameters
    {
        NameClaimType = "name"
    };
});

//// add automatic token management
//builder.Services.AddOpenIdConnectAccessTokenManagement(options =>
//{
//    // create and configure a DPoP JWK
//    //var rsaKey = new RsaSecurityKey(RSA.Create(2048));
//    //var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(rsaKey);
//    //jwk.Alg = "PS256";
//    //options.DPoPJsonWebKey = JsonSerializer.Serialize(jwk);

//    //var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(rsaCertificateKey);
//    //jwk.Alg = "PS256";
//    //options.DPoPJsonWebKey = JsonSerializer.Serialize(jwk);

//    var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(ecdsaCertificateKey);
//    jwk.Alg = "ES384";
//    options.DPoPJsonWebKey = DPoPProofKey.ParseOrDefault(JsonSerializer.Serialize(jwk));
//});

services.AddControllersWithViews(options =>
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

services.AddRazorPages().AddMvcOptions(options =>
{
    //var policy = new AuthorizationPolicyBuilder()
    //    .RequireAuthenticatedUser()
    //    .Build();
    //options.Filters.Add(new AuthorizeFilter(policy));
});

builder.Services.AddReverseProxy()
   .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();
// Do not add to deployments, for debug reasons
IdentityModelEventSource.ShowPII = true;

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error");
}

app.UseSecurityHeaders();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseNoUnauthorizedRedirect("/api");

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.MapNotFound("/api/{**segment}");

if (app.Environment.IsDevelopment())
{
    var uiDevServer = app.Configuration.GetValue<string>("UiDevServerUrl");
    if (!string.IsNullOrEmpty(uiDevServer))
    {
        app.MapReverseProxy();
    }
}

app.MapFallbackToPage("/_Host");

app.Run();
