using BffOpenId.Server.BackChannelLogout;
using Duende.IdentityModel;
using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace BffOpenId.Server.Controllers;

// See Duende IdentityServer original src:
// https://github.com/DuendeSoftware/Samples/tree/main/IdentityServer/v8/SessionManagement/Client
[Route("api/[controller]")]
[ApiController]
public class BackchannelLogoutController : ControllerBase
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<BackchannelLogoutController> _logger;
    private readonly IConfiguration _configuration;
    private readonly LogoutSessionManager _logoutSessionsManager;

    public BackchannelLogoutController(
        LogoutSessionManager logoutSessionsManager,
        ILogger<BackchannelLogoutController> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _logoutSessionsManager = logoutSessionsManager;
        _httpClient = httpClientFactory.CreateClient();
        _logger = logger;
        _configuration = configuration;
    }

    [HttpPost]
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Index([FromForm] string logout_token)
    {
        _logger.LogInformation("BC Logout event from server: {logout_token}", logout_token);

        // MvcHybridBackChannelBackChannel Backchannel Logout from the server
        Response.Headers.Append("Cache-Control", "no-cache, no-store");
        Response.Headers.Append("Pragma", "no-cache");

        try
        {
            var user = await ValidateLogoutTokenAsync(logout_token);

            // these are the sub & sid to signout
            var sub = user.FindFirst("sub")?.Value;
            var sid = user.FindFirst("sid")?.Value;

            _logoutSessionsManager.Add(sub, sid);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{Message}", ex.Message);
        }
        return BadRequest();
    }

    private async Task<ClaimsPrincipal> ValidateLogoutTokenAsync(string logoutToken)
    {
        var claims = await ValidateJwtAsync(logoutToken);

        if (claims.FindFirst("sub") == null && claims.FindFirst("sid") == null)
        {
            throw new Exception("BC Invalid logout token sub or sid is missing");
        }

        var nonce = claims.FindFirstValue("nonce");
        if (!string.IsNullOrWhiteSpace(nonce))
        {
            throw new Exception("BC Invalid logout token, nonce is present");
        }

        var eventsJson = claims.FindFirst("events")?.Value;
        if (string.IsNullOrWhiteSpace(eventsJson))
        {
            throw new Exception("BC Invalid logout token, missing events");
        }

        var events = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(eventsJson);
        var logoutEvent = events!.TryGetValue("http://schemas.openid.net/event/backchannel-logout", out var logoutTokenData);

        if (logoutEvent == false)
        {
            _logger.LogInformation("BC Invalid logout token {logoutTokenData}", logoutTokenData);
            // 2.6 Logout Token Validation
            throw new Exception("BC Invalid logout token");
        }

        return claims;
    }

    private async Task<ClaimsPrincipal> ValidateJwtAsync(string jwt)
    {
        var disco = await HttpClientDiscoveryExtensions.GetDiscoveryDocumentAsync(
           _httpClient, _configuration["WebOidcAuthority"]);

        var keys = new List<SecurityKey>();
        foreach (var webKey in disco.KeySet!.Keys)
        {
            var key = new JsonWebKey()
            {
                Kty = webKey.Kty,
                Alg = webKey.Alg,
                Kid = webKey.Kid,
                X = webKey.X,
                Y = webKey.Y,
                Crv = webKey.Crv,
                E = webKey.E,
                N = webKey.N,
            };
            keys.Add(key);
        }

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = disco.Issuer,
            ValidAudience = "webclient", //_configuration["WebOidcAuthority"],
            IssuerSigningKeys = keys,

            NameClaimType = JwtClaimTypes.Name,
            RoleClaimType = JwtClaimTypes.Role
        }; 

        var handler = new JwtSecurityTokenHandler();
        handler.InboundClaimTypeMap.Clear();

        var user = handler.ValidateToken(jwt, parameters, out var _);
        return user;
    }
}
