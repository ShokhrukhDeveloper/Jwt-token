using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Jwt.Service;
public class JwtTokenService : ITokenService
{
    IConfiguration _configuration;
    public JwtTokenService(IConfiguration configuration)
    {
        _configuration=configuration;
    }
    public string Create(Dictionary<string, string> calims)
    {
       var calimsJwt=calims.Select(c=> new Claim(c.Key,c.Value));
       var key=_configuration["Jwt:key"]?? throw new NullReferenceException("Jwt key is null");
       var issuer=_configuration["Jwt:Issuer"]??throw new NullReferenceException("Jwt Issuer is null");
       var audience=_configuration["Jwt:Audience"]??throw new NullReferenceException("Jwt Audience  is null");

       var securityKey=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
       var credential=new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
       var token=new JwtSecurityToken(
        issuer,
        audience,
        calimsJwt,
        expires:DateTime.Now.AddMinutes(100),
        signingCredentials:credential
       );
       return new JwtSecurityTokenHandler().WriteToken(token);

    //    var securityKey=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    }

    public bool Validate(string token)
    {
        var key=_configuration["Jwt:Key"]?? throw new NullReferenceException("Jwt key is null");
        var issuer=_configuration["Jwt:Issuer"]??throw new NullReferenceException("Jwt Issuer is null");
        var audience=_configuration["Jwt:Audience"]??throw new NullReferenceException("Jwt Audience  is null");

        var secret=Encoding.UTF8.GetBytes(key);
        var securityKey= new SymmetricSecurityKey(secret);
        var tokenHandler= new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(token,
            new TokenValidationParameters
            {
                    ValidateIssuerSigningKey=true,
                    ValidateIssuer=true,
                    ValidateAudience=true,
                    ValidIssuer=issuer,
                    ValidAudience=audience,
                    IssuerSigningKey=securityKey
            },out SecurityToken validatedToken
            );
            return true;
        }catch(Exception){
          return false;  
        }
        
    }
}