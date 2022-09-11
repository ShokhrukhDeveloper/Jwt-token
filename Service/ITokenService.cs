namespace Jwt.Service;
public interface ITokenService
{
    public string Create(Dictionary<string,string> calims);
    public bool Validate(string token);
    
}