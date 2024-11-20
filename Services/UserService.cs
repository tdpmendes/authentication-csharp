namespace WebApi.Services;

using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Models;

public interface IUserService
{
    Task<User> AuthenticateBasic(string username, string password);
    Task<IEnumerable<User>> GetAll();
    User? GetById(int id);
    AuthenticateResponse? AuthenticateJwt(AuthenticateRequest request);

}

public class UserService : IUserService
{
    private readonly IJwtUtils _jwtUtils;

    // users hardcoded for simplicity, store in a db with hashed passwords in production applications
    private List<User> _users = new List<User>
    {
        new User { Id = 1, FirstName = "Test", LastName = "User", Username = "test", Password = "test" }
    };

    public UserService(IJwtUtils jwtUtils)
    {
        _jwtUtils = jwtUtils;
    }

    public async Task<User> AuthenticateBasic(string username, string password)
    {
        // wrapped in "await Task.Run" to mimic fetching user from a db
        var user = await Task.Run(() => _users.SingleOrDefault(x => x.Username == username && x.Password == password));

        // on auth fail: null is returned because user is not found
        // on auth success: user object is returned
        return user;
    }

    public AuthenticateResponse? AuthenticateJwt(AuthenticateRequest request)
    {
        var user = _users.SingleOrDefault(x => x.Username == request.Username &&  x.Password == request.Password);

        if (user == null) return null;

        var token = _jwtUtils.GenerateJwtToken(user);

        return new AuthenticateResponse(user,token);
    }

    public async Task<IEnumerable<User>> GetAll()
    {
        // wrapped in "await Task.Run" to mimic fetching users from a db
        return await Task.Run(() => _users);
    }

    public User GetById(int id)
    {
        return _users.FirstOrDefault(x => x.Id == id);
    }
}
