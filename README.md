# Multiple Schemes with OpenID Connect

[![.NET](https://github.com/damienbod/MultipleSchemeWithOidc/actions/workflows/dotnet.yml/badge.svg)](https://github.com/damienbod/MultipleSchemeWithOidc/actions/workflows/dotnet.yml)

Blogs

[Use multiple schemes in a ASP.NET Core Web application](https://damienbod.com)

View serversidesessions on Duende:

```
https://localhost:5001/serversidesessions
```

## Setup:

```
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Unknown";
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddPolicyScheme("Unknown", "Select SchemeOne/SchemeTwo", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        if (context.Request.Cookies.ContainsKey("__Host-Http-one"))
            return "SchemeOne";

        if (context.Request.Cookies.ContainsKey("__Host-Http-two"))
            return "SchemeTwo";

        return "SchemeOne"; // fallback
    };
})
.AddCookie("SchemeOne", options =>
{
    options.Cookie.Name = "__Host-Http-one";
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.EventsType = typeof(CookieEventHandler);
})
.AddCookie("SchemeTwo", options =>
{
    options.Cookie.Name = "__Host-Http-two";
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.EventsType = typeof(CookieEventHandler);
})
.AddCookie("SchemeOidcAuth")
.AddOpenIdConnect(options =>
{
    options.SignInScheme = "SchemeOidcAuth";
    // ... 
}
```

## History
- 2026-10-09 Initial version of the project.

## Links

https://learn.microsoft.com/en-us/aspnet/core/security/authorization/authorize-with-a-specific-scheme

https://github.com/DuendeSoftware/Samples/tree/main/IdentityServer/v8/SessionManagement/Client

https://aspire.dev/