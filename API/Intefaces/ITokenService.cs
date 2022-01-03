
using API.Entities;

namespace API.Intefaces;
public interface ITokenService
{
    Task<string> CreateToken(AppUser user);
}