using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace BffOpenId.Server.Controllers;

[ValidateAntiForgeryToken]
[Authorize(AuthenticationSchemes = "SchemeOne")]
[ApiController]
[Route("api/[controller]")]
public class SchemOneController : ControllerBase
{
    [HttpGet]
    public IEnumerable<string> Get()
    {
        return new List<string> { "some data scheme 1", "more data", "loads of data" };
    }
}
