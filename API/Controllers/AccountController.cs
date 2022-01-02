
using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTO;
using API.Entities;
using API.Intefaces;
using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;
public class AccountController : BaseApiController
{
    private readonly DataContext _context;
    private readonly ITokenService _tokenService;
    private readonly IMapper _mapper;
    public AccountController(DataContext context, ITokenService tokenService, IMapper mapper)
    {
        _mapper = mapper;
        _tokenService = tokenService;
        _context = context;

    }

    [HttpPost("register")]
    public async Task<ActionResult<UserDto>> Register(RegisterDto register)
    {
        if (await UserExists(register.Username)) return BadRequest("Username is taken");

        var user = _mapper.Map<AppUser>(register);

        using var hmac = new HMACSHA512();
        user.UserName = register.Username.ToLower();
        user.PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(register.Password));
        user.PasswordSalt = hmac.Key;
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user),
            KnownAs = user.KnownAs
        };
    }

    private async Task<bool> UserExists(string username)
    {
        return await _context.Users.AnyAsync(match => match.UserName == username.ToLower());
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto login)
    {
        var user = await _context.Users
        .Include(p => p.Photos)
        .SingleOrDefaultAsync(match => match.UserName == login.Username);

        if (user == null) return Unauthorized("Invalid Username or Password1.");
        using var hmac = new HMACSHA512(user.PasswordSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(login.Password));
        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid username or Password2.");
        }

        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user),
            PhotoUrl = user.Photos.FirstOrDefault(x => x.IsMain)?.Url,
            KnownAs = user.KnownAs
        };

    }
}
