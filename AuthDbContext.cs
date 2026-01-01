using FreshFarmMarket.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FreshFarmMarket;

public class AuthDbContext(IConfiguration configuration) : IdentityDbContext<User>
{
    public DbSet<AuditLog> AuditLogs { get; set; }
    public DbSet<PasswordHistory> PasswordHistories { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        var connectionString = configuration.GetConnectionString("Default");
        options.UseSqlite(connectionString);
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder
            .Entity<AuditLog>()
            .HasOne(a => a.User)
            .WithMany()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder
            .Entity<PasswordHistory>()
            .HasOne(p => p.User)
            .WithMany()
            .HasForeignKey(p => p.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
