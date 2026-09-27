using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BffOpenId.Server.Controllers;

[ValidateAntiForgeryToken]
[Authorize(AuthenticationSchemes = "SchemeTwo")]
[ApiController]
[Route("api/[controller]")]
public class SchemeTwoController : ControllerBase
{
    [HttpGet]
    public IEnumerable<string> Get()
    {
        return new List<string> { "some data scheme 2", "more data", "loads of data" };
    }
}
