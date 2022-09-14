using Jwt.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Jwt.Controller;
[ApiController]
[Route("api/[controller]")]
public class HomeController:ControllerBase
{
    ITokenService _tokenService;
    public HomeController(ITokenService tokenService)
    {
        _tokenService=tokenService;
    }
    [HttpPost]
    public IActionResult Login([FromServices]ITokenService tokenService,string userName , string password){

        if(userName=="admin"&&password=="admin")
        return Ok(
            tokenService.Create(
                new Dictionary<string, string>{
                    {"role","nor"},
                    {"username","admin"},
                    {"password","admin"},
                    {"dob",DateTime.Now.AddYears(-25).ToString()},
                }
            )
        );

        return Forbid();
    }
    [Authorize]
    [HttpGet]
    public IActionResult secret()=>Ok("ok");
    

}