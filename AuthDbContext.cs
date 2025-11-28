using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket;

public class AuthDbContext(IConfiguration configuration) : IdentityDbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        var connectionString = configuration.GetConnectionString("Default");
        options.UseSqlServer(connectionString);
    }
}